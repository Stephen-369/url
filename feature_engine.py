# feature_engine.py
import re
from urllib.parse import urlparse
import numpy as np
import tldextract

class FeatureExtractor:
    def __init__(self):
        # 预设的恶意特征黑名单与字典
        self.suspicious_tlds =['.xyz', '.top', '.pw', '.cc', '.club', '.asia', '.ru']
        self.shorteners =['bit.ly', 't.cn', 'tinyurl.com', 'goo.gl', 'is.gd', 'ow.ly']
        self.banking_words =['paypal', 'bank', 'account', 'pay', 'wallet', 'crypto']

    def preprocess_url(self, url):
        """预处理：如果用户没有输入协议头，自动补全以便解析"""
        url = url.strip().lower()
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        return url

    def extract_features(self, url):
        """
        核心特征提取引擎：将单条URL转化为论文中描述的特征向量 (一维NumPy数组)
        提取维度包括：词法与长度统计、主机与网络属性、语义关键词
        """
        url = self.preprocess_url(url)
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        domain = parsed.netloc
        path = parsed.path
        
        # ================= 1. 词法与长度统计特征 =================
        url_length = len(url)
        domain_length = len(domain)
        path_length = len(path)
        
        count_hyphen = url.count('-')
        count_at = url.count('@')
        count_dot = url.count('.')
        # 排除 http:// 的双斜杠
        count_double_slash = url[url.find('//')+2:].count('//')
        
        # 数字字符比例
        digits_count = sum(c.isdigit() for c in url)
        digit_ratio = digits_count / url_length if url_length > 0 else 0.0

        # ================= 2. 主机与网络属性特征 =================
        # 检查是否为 IP 直连 (简单的正则匹配 IPv4)
        use_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]) else 0
        
        # 检查可疑 TLD
        tld = '.' + ext.suffix
        suspicious_tld = 1 if tld in self.suspicious_tlds else 0
        
        # 检查短链接
        is_shortened = 1 if ext.domain + '.' + ext.suffix in self.shorteners else 0
        
        # 子域名层级深度 (按点号分割子域名)
        subdomain_level = len(ext.subdomain.split('.')) if ext.subdomain else 0

        # ================= 3. 敏感关键词与语义特征 =================
        has_login = 1 if 'login' in url else 0
        has_admin = 1 if 'admin' in url else 0
        has_secure = 1 if 'secure' in url else 0
        has_update = 1 if 'update' in url else 0
        
        # 检查金融/账户词汇
        has_banking = 1 if any(word in url for word in self.banking_words) else 0

        # 组合为特征列表 (顺序需与模型训练时绝对一致)
        feature_vector =[
            url_length, domain_length, path_length, count_hyphen, count_at,
            count_dot, count_double_slash, digit_ratio, use_ip, suspicious_tld,
            is_shortened, subdomain_level, has_login, has_admin, has_secure,
            has_update, has_banking
        ]
        
        return np.array(feature_vector).reshape(1, -1)

# 测试代码
if __name__ == "__main__":
    extractor = FeatureExtractor()
    test_url = "https://secure-login.paypal-update.com/auth"
    features = extractor.extract_features(test_url)
    print(f"提取成功，特征向量形状: {features.shape}")
    print(f"特征向量内容: {features}")