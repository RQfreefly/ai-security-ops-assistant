import unittest
from unittest.mock import Mock, patch
import json
from ai_analyzer import AIAnalyzer

class TestAIAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = AIAnalyzer()
        self.sample_alert = {
            "alert_type": "可疑连接",
            "timestamp": "2024-03-20T10:00:00Z",
            "event": {
                "source": {
                    "ip": "192.168.1.100",
                    "port": 12345
                },
                "target": {
                    "ip": "10.0.0.1",
                    "port": 80
                },
                "protocol": "TCP",
                "description": "检测到可疑的远程连接尝试"
            }
        }

    def test_format_alert(self):
        """测试告警格式化功能"""
        formatted = self.analyzer._format_alert(self.sample_alert)
        formatted_dict = json.loads(formatted)
        
        self.assertEqual(formatted_dict["告警类型"], "可疑连接")
        self.assertEqual(formatted_dict["源IP"], "192.168.1.100")
        self.assertEqual(formatted_dict["目标IP"], "10.0.0.1")
        self.assertEqual(formatted_dict["协议"], "TCP")

    def test_extract_decision(self):
        """测试响应决策提取功能"""
        # 测试标准格式
        analysis = """
        分析结果...
        响应决策：是
        决策原因：这是一个高危攻击
        """
        decision, reason = self.analyzer._extract_decision(analysis)
        self.assertTrue(decision)
        self.assertEqual(reason, "这是一个高危攻击")

        # 测试替代格式
        analysis = """
        分析结果...
        • 响应决策：否
        • 决策原因：误报
        """
        decision, reason = self.analyzer._extract_decision(analysis)
        self.assertFalse(decision)
        self.assertEqual(reason, "误报")

    @patch('ai_analyzer.Generation.call')
    @patch('ai_analyzer.ThreatIntel')
    def test_analyze_alert(self, mock_threat_intel, mock_generation):
        """测试告警分析功能"""
        # 模拟威胁情报返回
        mock_threat_intel.return_value.get_ip_info.return_value = {
            "country": "中国",
            "city": "北京",
            "org": "测试ISP"
        }
        mock_threat_intel.return_value.get_vt_ip_report.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2
                    }
                }
            }
        }

        # 模拟AI分析返回
        mock_generation.return_value.output.choices = [
            Mock(message=Mock(content="""
            分析结果...
            响应决策：是
            决策原因：确认是恶意IP
            """))
        ]

        result = self.analyzer.analyze_alert(self.sample_alert)
        
        self.assertIn("analysis", result)
        self.assertIn("threat_intel", result)
        self.assertIn("response_decision", result)
        self.assertTrue(result["response_decision"]["should_respond"])
        self.assertEqual(result["response_decision"]["reason"], "确认是恶意IP")

    @patch('ai_analyzer.ResponseActions')
    def test_execute_response(self, mock_response_actions):
        """测试响应动作执行功能"""
        mock_response_actions.return_value.block_ip.return_value = {
            "success": True,
            "message": "IP已成功封禁"
        }

        result = self.analyzer.execute_response("192.168.1.100")
        
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "IP已成功封禁")
        mock_response_actions.return_value.block_ip.assert_called_once_with("192.168.1.100")

if __name__ == '__main__':
    unittest.main() 