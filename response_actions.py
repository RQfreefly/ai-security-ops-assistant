import requests
from typing import Dict, List
from config import settings

class ResponseActions:
    """
    响应动作服务类
    
    该类负责执行安全响应动作，如：
    - 封锁IP地址
    - 解除IP地址封锁
    - 查看当前封锁状态
    
    属性:
        firewall_api_url: 防火墙API的URL地址
    """
    
    def __init__(self):
        """初始化响应动作服务，设置防火墙API地址"""
        self.firewall_api_url = settings.FIREWALL_API_URL
    
    def block_ip(self, ip: str, duration: int = 3600) -> Dict:
        """
        在防火墙上封锁IP地址
        
        参数:
            ip: 要封锁的IP地址
            duration: 封锁持续时间（秒），默认1小时
            
        返回:
            Dict: 包含封锁操作结果的字典
        """
        try:
            response = requests.post(
                f"{self.firewall_api_url}/block",
                json={
                    "ip": ip,
                    "duration": duration,
                    "reason": "Suspicious activity detected"
                }
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def unblock_ip(self, ip: str) -> Dict:
        """
        解除IP地址封锁
        
        参数:
            ip: 要解除封锁的IP地址
            
        返回:
            Dict: 包含解除封锁操作结果的字典
        """
        try:
            response = requests.post(
                f"{self.firewall_api_url}/unblock",
                json={"ip": ip}
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_blocked_ips(self) -> List[Dict]:
        """
        获取当前被封锁的IP列表
        
        返回:
            List[Dict]: 包含所有被封锁IP信息的列表
        """
        try:
            response = requests.get(f"{self.firewall_api_url}/blocked")
            return response.json()
        except Exception as e:
            return [{"error": str(e)}] 