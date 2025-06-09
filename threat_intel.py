import requests
from typing import Dict, Optional
from config import settings
import time

class ThreatIntel:
    """
    威胁情报服务类
    
    该类负责从各种威胁情报源获取信息，包括：
    - IPInfo: 获取IP地址的地理位置和网络信息
    - VirusTotal: 获取IP地址和文件的威胁情报
    
    属性:
        vt_api_key: VirusTotal API密钥
        ipinfo_api_key: IPInfo API密钥
    """
    
    def __init__(self):
        """初始化威胁情报服务，设置API密钥"""
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.ipinfo_api_key = settings.IPINFO_API_KEY
        
    def get_ip_info(self, ip: str) -> Dict:
        """
        获取IP地址的详细信息
        
        参数:
            ip: 要查询的IP地址
            
        返回:
            Dict: 包含IP地址详细信息的字典，包括地理位置、ISP等信息
        """
        if not self.ipinfo_api_key:
            return {"error": "IPInfo API key not configured"}
            
        try:
            response = requests.get(
                f"https://ipinfo.io/{ip}",
                headers={"Authorization": f"Bearer {self.ipinfo_api_key}"}
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_vt_ip_report(self, ip: str) -> Dict:
        """
        获取VirusTotal的IP报告
        
        参数:
            ip: 要查询的IP地址
            
        返回:
            Dict: 包含VirusTotal对IP地址的分析报告
        """
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured"}
            
        try:
            response = requests.get(
                f"https://www.virustotal.com/vtapi/v2/ip-address/report",
                params={"apikey": self.vt_api_key, "ip": ip}
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_vt_file_report(self, file_hash: str) -> Dict:
        """
        获取VirusTotal的文件报告
        
        参数:
            file_hash: 文件的MD5/SHA1/SHA256哈希值
            
        返回:
            Dict: 包含VirusTotal对文件的分析报告
        """
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured"}
            
        try:
            response = requests.get(
                f"https://www.virustotal.com/vtapi/v2/file/report",
                params={"apikey": self.vt_api_key, "resource": file_hash}
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)} 