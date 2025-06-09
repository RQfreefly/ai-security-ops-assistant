import unittest
from unittest.mock import patch, Mock
from threat_intel import ThreatIntel

class TestThreatIntel(unittest.TestCase):
    def setUp(self):
        self.threat_intel = ThreatIntel()
        self.test_ip = "8.8.8.8"
        self.test_hash = "44d88612fea8a8f36de82e1278abb02f"

    @patch('requests.get')
    def test_get_ip_info_success(self, mock_get):
        """测试成功获取IP信息"""
        # 模拟成功的API响应
        mock_response = Mock()
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "org": "Google LLC"
        }
        mock_get.return_value = mock_response

        result = self.threat_intel.get_ip_info(self.test_ip)
        
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["city"], "Mountain View")
        self.assertEqual(result["org"], "Google LLC")
        mock_get.assert_called_once()

    @patch('requests.get')
    def test_get_ip_info_error(self, mock_get):
        """测试获取IP信息失败的情况"""
        # 模拟API请求失败
        mock_get.side_effect = Exception("API请求失败")

        result = self.threat_intel.get_ip_info(self.test_ip)
        
        self.assertIn("error", result)
        self.assertEqual(result["error"], "API请求失败")

    @patch('requests.get')
    def test_get_vt_ip_report_success(self, mock_get):
        """测试成功获取VirusTotal IP报告"""
        # 模拟成功的API响应
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 50
                    }
                }
            }
        }
        mock_get.return_value = mock_response

        result = self.threat_intel.get_vt_ip_report(self.test_ip)
        
        self.assertIn("data", result)
        self.assertIn("attributes", result["data"])
        self.assertIn("last_analysis_stats", result["data"]["attributes"])
        mock_get.assert_called_once()

    @patch('requests.get')
    def test_get_vt_file_report_success(self, mock_get):
        """测试成功获取VirusTotal文件报告"""
        # 模拟成功的API响应
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 3,
                        "undetected": 40
                    }
                }
            }
        }
        mock_get.return_value = mock_response

        result = self.threat_intel.get_vt_file_report(self.test_hash)
        
        self.assertIn("data", result)
        self.assertIn("attributes", result["data"])
        self.assertIn("last_analysis_stats", result["data"]["attributes"])
        mock_get.assert_called_once()

    def test_get_ip_info_no_api_key(self):
        """测试没有API密钥时获取IP信息"""
        self.threat_intel.ipinfo_api_key = None
        result = self.threat_intel.get_ip_info(self.test_ip)
        self.assertIn("error", result)
        self.assertEqual(result["error"], "IPInfo API key not configured")

    def test_get_vt_report_no_api_key(self):
        """测试没有API密钥时获取VirusTotal报告"""
        self.threat_intel.vt_api_key = None
        result = self.threat_intel.get_vt_ip_report(self.test_ip)
        self.assertIn("error", result)
        self.assertEqual(result["error"], "VirusTotal API key not configured")

if __name__ == '__main__':
    unittest.main() 