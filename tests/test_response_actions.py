import unittest
from unittest.mock import patch, Mock
from response_actions import ResponseActions

class TestResponseActions(unittest.TestCase):
    def setUp(self):
        self.response_actions = ResponseActions()
        self.test_ip = "192.168.1.100"

    @patch('requests.post')
    def test_block_ip_success(self, mock_post):
        """测试成功封锁IP"""
        # 模拟成功的API响应
        mock_response = Mock()
        mock_response.json.return_value = {
            "success": True,
            "message": "IP已成功封禁",
            "blocked_until": "2024-03-21T10:00:00Z"
        }
        mock_post.return_value = mock_response

        result = self.response_actions.block_ip(self.test_ip)
        
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "IP已成功封禁")
        mock_post.assert_called_once()

    @patch('requests.post')
    def test_block_ip_error(self, mock_post):
        """测试封锁IP失败的情况"""
        # 模拟API请求失败
        mock_post.side_effect = Exception("API请求失败")

        result = self.response_actions.block_ip(self.test_ip)
        
        self.assertIn("error", result)
        self.assertEqual(result["error"], "API请求失败")

    @patch('requests.post')
    def test_unblock_ip_success(self, mock_post):
        """测试成功解除IP封锁"""
        # 模拟成功的API响应
        mock_response = Mock()
        mock_response.json.return_value = {
            "success": True,
            "message": "IP已成功解除封禁"
        }
        mock_post.return_value = mock_response

        result = self.response_actions.unblock_ip(self.test_ip)
        
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "IP已成功解除封禁")
        mock_post.assert_called_once()

    @patch('requests.post')
    def test_unblock_ip_error(self, mock_post):
        """测试解除IP封锁失败的情况"""
        # 模拟API请求失败
        mock_post.side_effect = Exception("API请求失败")

        result = self.response_actions.unblock_ip(self.test_ip)
        
        self.assertIn("error", result)
        self.assertEqual(result["error"], "API请求失败")

    @patch('requests.get')
    def test_get_blocked_ips_success(self, mock_get):
        """测试成功获取被封禁IP列表"""
        # 模拟成功的API响应
        mock_response = Mock()
        mock_response.json.return_value = [
            {
                "ip": "192.168.1.100",
                "blocked_until": "2024-03-21T10:00:00Z",
                "reason": "Suspicious activity detected"
            },
            {
                "ip": "192.168.1.101",
                "blocked_until": "2024-03-21T11:00:00Z",
                "reason": "Malware detected"
            }
        ]
        mock_get.return_value = mock_response

        result = self.response_actions.get_blocked_ips()
        
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["ip"], "192.168.1.100")
        self.assertEqual(result[1]["ip"], "192.168.1.101")
        mock_get.assert_called_once()

    @patch('requests.get')
    def test_get_blocked_ips_error(self, mock_get):
        """测试获取被封禁IP列表失败的情况"""
        # 模拟API请求失败
        mock_get.side_effect = Exception("API请求失败")

        result = self.response_actions.get_blocked_ips()
        
        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])
        self.assertEqual(result[0]["error"], "API请求失败")

if __name__ == '__main__':
    unittest.main() 