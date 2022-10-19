package src

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/520MianXiangDuiXiang520/GoTools/json"
	path2 "github.com/520MianXiangDuiXiang520/GoTools/path"

	"simple_ca/src/definition"
	"simple_ca/src/tools"
)

// AuthSetting 认证相关配置
type AuthSetting struct {
	TokenExpireTime int64 `json:"token_expire_time"` // token 过期时间，分钟
}

// Secret 加密和证书相关配置
type Secret struct {
	ResponseSecret           string                                `json:"response_secret"`
	CARootPrvKeyName         string                                `json:"ca_root_private_key_name"`
	CARootPrvKeyLen          int                                   `json:"ca_root_private_key_len"`
	UserCerPath              string                                `json:"user_cer_path"` // 证书保存的文件夹名称 在项目根目录
	CARootCertName           string                                `json:"ca_root_cer_name"`
	CAIssuerInfo             *definition.CertificateSigningRequest `json:"ca_issuer_info"`
	CertificateEffectiveTime int64                                 `json:"certificate_effective_time"` // 证书有效时长，单位天
	DownloadLink             string                                `json:"download_link"`              // 证书下载路径
}

// SMTPSetting SMTP 连接相关配置
type SMTPSetting struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// CRLSetting CRL 相关配置
type CRLSetting struct {
	CRLFileName          string `json:"crl_file_name"`          // CRL 文件名
	CRLDistributionPoint string `json:"crl_distribution_point"` // CRL 分发点
	CrlUpdateInterval    int    `json:"crl_update_interval"`    // CRL 信息更新间隔
}

// AuthorityInfoAccess 授权访问信息相关配置
type AuthorityInfoAccess struct {
	IssuingCertificateURL string `json:"issuing_certificate_url"` // 颁发者根证书路径
}

type MySQLConn struct {
	Engine    string        `json:"engine"`
	DBName    string        `json:"db_name"`
	User      string        `json:"user"`
	Password  string        `json:"password"`
	Host      string        `json:"host"`
	Port      int           `json:"port"`
	MIdleConn int           `json:"max_idle_conn"` // 最大空闲连接数
	MOpenConn int           `json:"max_open_conn"` // 最大打开连接数
	MLifetime time.Duration `json:"max_lifetime"`  // 连接超时时间
	LogMode   bool          `json:"log_mode"`
}

type Setting struct {
	Database            *MySQLConn           `json:"database"`
	AuthSetting         *AuthSetting         `json:"auth_setting"`
	Secret              *Secret              `json:"secret"`
	SMTPSetting         *SMTPSetting         `json:"smtp_setting"`
	SiteLink            string               `json:"site_link"`
	CRLSetting          *CRLSetting          `json:"crl_setting"`
	CSRFileKey          string               `json:"csr_file_key"`
	AuthorityInfoAccess *AuthorityInfoAccess `json:"authority_info_access"`
}

var setting *Setting
var settingLock sync.Mutex
var caOnce, crlOnce sync.Once

func InitSetting(filePath string) {
	defer func() {
		if e := recover(); e != nil {
			settingLock.Unlock()
		}
	}()
	filename := filePath
	if !path2.IsAbs(filePath) {
		_, currently, _, _ := runtime.Caller(1)
		filename = path.Join(path.Dir(currently), filePath)
	}
	if setting == nil {
		settingLock.Lock()
		if setting == nil {
			err := json.FromFileLoadToObj(&setting, filename)
			if err != nil {
				panic("read setting error!")
			}
		}
		settingLock.Unlock()
	}
}

func GetSetting() *Setting {
	if setting == nil {
		panic("setting Uninitialized！")
	}
	return setting
}

var CARootCert = &x509.Certificate{}
var CARootPrvKey = &rsa.PrivateKey{}

// loadCACertAndPrvKey 加载 CA 私钥和根证书
func loadCACertAndPrvKey() (rootRCer *x509.Certificate, rootRPK *rsa.PrivateKey) {
	// 获取私钥
	currentPath, _ := os.Getwd()
	prvKeyName := GetSetting().Secret.CARootPrvKeyName
	prvKeyFilepath := path.Join(currentPath, prvKeyName)
	if !tools.IsFileExist(prvKeyFilepath) {
		// 私钥不存在，创建
		if !tools.CreateRSAPrivateKeyToFile(prvKeyFilepath, GetSetting().Secret.CARootPrvKeyLen) {
			panic("CAPrivateKeyAcquisitionFailed")
		}
	}

	data, err := os.ReadFile(prvKeyFilepath)
	if err != nil {
		tools.ExceptionLog(err, fmt.Sprintf("open %s Fail", prvKeyFilepath))
		panic("CAPrivateKeyAcquisitionFailed")
	}
	r, ok := tools.DecodeRSAPrivateKey(data)
	rootRPK = r
	if !ok {
		panic("CAPrivateKeyAcquisitionFailed")
	}

	// 加载证书
	s := GetSetting().Secret.CAIssuerInfo
	issuer := pkix.Name{
		Country:            []string{s.Country},
		Province:           []string{s.Province},
		Locality:           []string{s.Locality},
		Organization:       []string{s.Organization},
		OrganizationalUnit: []string{s.OrganizationalUnit},
		CommonName:         s.CommonName,
	}
	certName := GetSetting().Secret.CARootCertName
	certFilepath := path.Join(currentPath, certName)
	if !tools.IsFileExist(certFilepath) {
		// 新建证书
		if !tools.CreateIssuerRootCer(issuer,
			time.Now(), time.Now().Add(time.Hour*24*365*10), r, certName) {
			panic("FailedToCreateRootCertificate")
		}
	}
	// 读根证书
	rootRCer, ok = tools.DecodePemCert(certFilepath)
	if !ok {
		panic("DecodeRootCertificateFail")
	}
	return
}

func GetCARootCert() (x509.Certificate, rsa.PrivateKey) {
	caOnce.Do(func() {
		CARootCert, CARootPrvKey = loadCACertAndPrvKey()
	})
	return *CARootCert, *CARootPrvKey
}

var crlUpdateTimeNextTime int64

// GetNextUpdateCRLTime 获取下一次更新 CRL 的时间
func GetNextUpdateCRLTime() int64 {
	if atomic.LoadInt64(&crlUpdateTimeNextTime) == 0 {
		crlOnce.Do(func() {
			t, ok := tools.ParseCRLUpdateTime(GetSetting().CRLSetting.CRLFileName)
			if !ok {
				atomic.StoreInt64(&crlUpdateTimeNextTime, time.Now().Unix())
			} else {
				atomic.StoreInt64(&crlUpdateTimeNextTime, t)
			}
		})
	}
	return atomic.LoadInt64(&crlUpdateTimeNextTime)
}

func SetNextUpdateCRLTime(n int64) {
	atomic.StoreInt64(&crlUpdateTimeNextTime, n)
}
