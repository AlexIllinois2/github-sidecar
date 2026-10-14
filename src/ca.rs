//! 根 CA 生成/加载，以及按域名即时签发叶证书（MITM 用）。
//! 只在启用 MITM 的规则上才会用到 CA；纯 DNS/直连加速完全不需要装证书。

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::{Duration as TimeDuration, OffsetDateTime};

pub struct CaManager {
    dir: PathBuf,
    /// 用加载出的参数在内存里重建的 CA 证书对象（仅作签发叶证书时的 issuer，
    /// 它的签名与磁盘上的 ca.crt 不同，因此不能用来算指纹）
    ca_signer: rcgen::Certificate,
    ca_key: Mutex<KeyPair>,
    /// 磁盘上 ca.crt 的原始 DER：指纹必须基于它，否则用户无法核对下载的证书
    ca_cert_der: CertificateDer<'static>,
    ca_pem: String,
    leaf_cache: Mutex<HashMap<String, std::sync::Arc<ServerConfig>>>,
}

impl CaManager {
    /// 初始化 CA：不存在则生成并落盘（ca.crt / ca.key.pem），存在则加载。
    pub fn init(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("创建数据目录失败: {}", dir.display()))?;
        let crt = dir.join("ca.crt");
        let key = dir.join("ca.key.pem");
        let (ca_pem, key_pem) = if crt.exists() && key.exists() {
            (
                std::fs::read_to_string(&crt).context("读取 ca.crt 失败")?,
                std::fs::read_to_string(&key).context("读取 ca.key.pem 失败")?,
            )
        } else {
            let (pem, kpem) = generate_ca().context("生成根 CA 失败")?;
            std::fs::write(&crt, &pem)?;
            std::fs::write(&key, &kpem)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
            }
            (pem, kpem)
        };

        let params = CertificateParams::from_ca_cert_pem(&ca_pem)
            .context("解析已有根证书失败（证书文件可能损坏）")?;
        let key_der = PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes())
            .context("解析 CA 私钥失败（PKCS#8 PEM）")?;
        let ca_key = KeyPair::try_from(key_der.secret_pkcs8_der())
            .context("加载 CA 私钥失败")?;
        // 用同一把私钥重建 issuer 对象：subject/SAN/有效期与磁盘上的 ca.crt 一致，
        // 公钥相同，因此叶证书链可被浏览器正确校验到已安装的根证书上。
        let ca_signer = params
            .self_signed(&ca_key)
            .context("重建 CA 签发对象失败")?;
        // 指纹要用文件里的原始 DER，重建出来的那份签名不同、指纹也不同
        let ca_cert_der = CertificateDer::from_pem_slice(ca_pem.as_bytes())
            .context("解析 ca.crt 失败")?;

        Ok(Self {
            dir: dir.to_path_buf(),
            ca_signer,
            ca_key: Mutex::new(ca_key),
            ca_cert_der,
            ca_pem,
            leaf_cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_file(&self) -> PathBuf {
        self.dir.join("ca.crt")
    }

    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.ca_cert_der.as_ref());
        digest.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
    }

    /// 取（或生成）某个域名的 TLS 服务端配置
    pub fn server_config_for(&self, host: &str) -> Result<std::sync::Arc<ServerConfig>> {
        if let Some(cached) = self.leaf_cache.lock().unwrap().get(host) {
            return Ok(cached.clone());
        }
        let (leaf_cert, leaf_key) = self.issue_leaf(host)?;
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_cert, self.ca_cert_der.clone()], leaf_key.into())
            .context("构造 TLS 服务端配置失败")?;
        let cfg = std::sync::Arc::new(cfg);
        self.leaf_cache
            .lock()
            .unwrap()
            .insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }

    fn issue_leaf(&self, host: &str) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(vec![host.to_string()])
            .context("叶证书参数错误")?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - TimeDuration::days(1);
        params.not_after = now + TimeDuration::days(825);

        let leaf_key = KeyPair::generate().context("生成叶私钥失败")?;
        let issuer_key = self.ca_key.lock().unwrap();
        let leaf = params
            .signed_by(&leaf_key, &self.ca_signer, &issuer_key)
            .context("签发叶证书失败")?;
        let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der().to_vec());
        Ok((leaf.der().clone(), key_der))
    }
}

fn generate_ca() -> Result<(String, String)> {
    let mut params = CertificateParams::new(vec![])?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Dev Sidecar Rs Root CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "dev-sidecar-rs");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - TimeDuration::days(1);
    params.not_after = now + TimeDuration::days(3650);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_generate_and_issue() {
        let dir = std::env::temp_dir().join(format!("dsc-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = CaManager::init(&dir).expect("init ca");
        assert!(dir.join("ca.crt").exists());
        // 第二次加载已存在的 CA
        drop(ca);
        let ca = CaManager::init(&dir).expect("reload ca");
        let fp = ca.fingerprint();
        assert_eq!(fp.len(), 32 * 3 - 1);
        // 重载后指纹必须稳定，否则界面上显示的指纹对不上已安装的根证书
        let fp2 = CaManager::init(&dir).expect("reload ca again").fingerprint();
        assert_eq!(fp, fp2);
        let der = CertificateDer::from_pem_slice(ca.ca_pem().as_bytes()).unwrap();
        assert_eq!(&der[..], &ca.ca_cert_der[..]);
        let cfg = ca.server_config_for("example.com").expect("leaf");
        let cfg2 = ca.server_config_for("example.com").expect("leaf cached");
        assert!(std::sync::Arc::ptr_eq(&cfg, &cfg2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
