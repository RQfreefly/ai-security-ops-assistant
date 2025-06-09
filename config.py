from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

class Settings(BaseSettings):
    """
    配置类
    
    用于管理应用程序的配置信息，包括：
    - API密钥
    - 服务端点
    - 其他配置参数
    """
    
    # 通义千问API密钥
    DASHSCOPE_API_KEY: str
    
    # VirusTotal API密钥
    VIRUSTOTAL_API_KEY: str
    
    # IPInfo API密钥
    IPINFO_API_KEY: str
    
    # 防火墙API配置
    FIREWALL_API_URL: str = "http://firewall-api.example.com"
    FIREWALL_API_KEY: str
    
    class Config:
        """配置类设置"""
        env_file = ".env"
        case_sensitive = True

# 创建全局配置实例
settings = Settings() 