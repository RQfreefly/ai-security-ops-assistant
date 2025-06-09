from dashscope import Generation
from typing import Dict, Any, Tuple
from config import settings
from threat_intel import ThreatIntel
from response_actions import ResponseActions
import re
import logging
import json

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AIAnalyzer:
    """
    AI分析服务类
    
    该类负责使用大语言模型分析安全告警，主要功能包括：
    - 分析告警信息
    - 获取威胁情报
    - 生成分析报告
    - 提供响应建议
    - 执行响应动作
    
    属性:
        threat_intel: 威胁情报服务实例
        response_actions: 响应动作服务实例
        analysis_prompt_template: 告警分析提示模板
    """
    
    def __init__(self):
        """
        初始化AI分析服务
        
        设置威胁情报服务和响应动作服务，
        并配置告警分析提示模板
        """
        self.threat_intel = ThreatIntel()
        self.response_actions = ResponseActions()
        
        # 告警分析提示模板
        self.analysis_prompt_template = """
        你是一个专业的安全运营分析师。请分析以下安全告警并提供详细的分析报告：

        告警信息：
        {alert}

        威胁情报信息：
        {threat_intel}

        请提供以下分析：
        1. 告警概述：简要说明这个告警是什么
        2. 威胁等级评估：评估这个告警的严重程度（高/中/低）
        3. 攻击者分析：分析攻击者的特征和行为
        4. 影响范围：分析可能受到影响的系统和数据
        5. 建议的响应措施：提供具体的处置建议
        6. 响应决策：根据分析结果，给出是否应该执行响应动作的决策（是/否），并说明原因

        请用中文回答，并在最后一行单独列出响应决策，格式为：
        响应决策：[是/否]
        决策原因：[原因说明]
        """
    
    def _extract_decision(self, analysis: str) -> Tuple[bool, str]:
        """
        从分析结果中提取响应决策
        
        参数:
            analysis: AI分析结果文本
            
        返回:
            Tuple[bool, str]: (是否执行响应动作, 决策原因)
        """
        # 使用正则表达式匹配响应决策
        decision_pattern = r"响应决策：([是|否])\s*决策原因：(.*?)(?=\n|$)"
        match = re.search(decision_pattern, analysis, re.DOTALL)
        
        if match:
            decision = match.group(1) == "是"
            reason = match.group(2).strip()
            return decision, reason
            
        # 如果上面的模式没有匹配到，尝试其他可能的格式
        alt_pattern = r"•\s*响应决策：([是|否])\s*•\s*决策原因：(.*?)(?=\n|$)"
        match = re.search(alt_pattern, analysis, re.DOTALL)
        
        if match:
            decision = match.group(1) == "是"
            reason = match.group(2).strip()
            return decision, reason
            
        return False, "无法从分析结果中提取决策信息"
    
    def _format_alert(self, alert: Dict[str, Any]) -> str:
        """
        格式化告警信息，提取关键字段
        
        参数:
            alert: 原始告警信息
            
        返回:
            str: 格式化后的告警信息
        """
        try:
            # 提取关键字段
            event = alert.get("event", {})
            source = event.get("source", {})
            target = event.get("target", {})
            
            formatted_alert = {
                "告警类型": alert.get("alert_type", "未知"),
                "告警时间": alert.get("timestamp", "未知"),
                "源IP": source.get("ip", "未知"),
                "源端口": source.get("port", "未知"),
                "目标IP": target.get("ip", "未知"),
                "目标端口": target.get("port", "未知"),
                "协议": event.get("protocol", "未知"),
                "事件描述": event.get("description", "未知")
            }
            
            return json.dumps(formatted_alert, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"格式化告警信息失败: {str(e)}")
            return str(alert)
    
    def _format_threat_intel(self, threat_intel: Dict[str, Any]) -> str:
        """
        格式化威胁情报信息，提取关键字段
        
        参数:
            threat_intel: 原始威胁情报信息
            
        返回:
            str: 格式化后的威胁情报信息
        """
        try:
            formatted_intel = {
                "IP信息": {
                    "国家": threat_intel.get("ip_info", {}).get("country", "未知"),
                    "城市": threat_intel.get("ip_info", {}).get("city", "未知"),
                    "ISP": threat_intel.get("ip_info", {}).get("org", "未知")
                },
                "威胁情报": {
                    "恶意评分": threat_intel.get("vt_report", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                    "可疑评分": threat_intel.get("vt_report", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0)
                }
            }
            
            return json.dumps(formatted_intel, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"格式化威胁情报失败: {str(e)}")
            return str(threat_intel)
    
    def analyze_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析安全告警并生成响应建议
        
        参数:
            alert: 包含告警信息的字典
            
        返回:
            Dict[str, Any]: 包含分析结果、威胁情报和响应决策的字典
        """
        try:
            # 获取威胁情报
            source_ip = alert["event"]["source"]["ip"]
            threat_intel = {
                "ip_info": self.threat_intel.get_ip_info(source_ip),
                "vt_report": self.threat_intel.get_vt_ip_report(source_ip)
            }
            
            # 格式化告警和威胁情报信息
            formatted_alert = self._format_alert(alert)
            formatted_threat_intel = self._format_threat_intel(threat_intel)
            
            # 构建提示
            prompt = self.analysis_prompt_template.format(
                alert=formatted_alert,
                threat_intel=formatted_threat_intel
            )
            
            logger.info("正在调用通义千问API...")
            
            # 调用通义千问API
            try:
                response = Generation.call(
                    model="qwen-max",
                    prompt=prompt,
                    temperature=0.7,
                    api_key=settings.DASHSCOPE_API_KEY,
                    result_format='message',
                    max_tokens=2000,
                    top_p=0.8,
                    enable_search=True
                )
                
                if not response or not response.output or not response.output.choices:
                    raise Exception("API返回结果无效")
                
                analysis_result = response.output.choices[0].message.content
                logger.info("成功获取分析结果")
                
                # 提取响应决策
                should_respond, decision_reason = self._extract_decision(analysis_result)
                
                return {
                    "analysis": analysis_result,
                    "threat_intel": threat_intel,
                    "response_decision": {
                        "should_respond": should_respond,
                        "reason": decision_reason
                    }
                }
            except Exception as api_error:
                logger.error(f"API调用失败: {str(api_error)}")
                raise
            
        except Exception as e:
            logger.error(f"分析过程出错: {str(e)}")
            return {
                "analysis": f"AI分析出错：{str(e)}",
                "threat_intel": {},
                "response_decision": {
                    "should_respond": False,
                    "reason": f"分析过程出错：{str(e)}"
                }
            }
    
    def execute_response(self, ip: str) -> Dict[str, Any]:
        """
        执行响应动作
        
        参数:
            ip: 要执行响应动作的IP地址
            
        返回:
            Dict[str, Any]: 包含响应动作执行结果的字典
        """
        return self.response_actions.block_ip(ip) 