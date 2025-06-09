import json
import typer
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from ai_analyzer import AIAnalyzer

# 创建Typer应用实例
app = typer.Typer()
# 创建Rich控制台实例
console = Console()

@app.command()
def analyze(
    alert_file: str = typer.Option(..., help="告警JSON文件路径"),
    force_execute: bool = typer.Option(False, help="强制执行响应动作，忽略AI决策")
):
    """
    分析安全告警并提供响应建议
    
    参数:
        alert_file: 包含告警信息的JSON文件路径
        force_execute: 是否强制执行响应动作，忽略AI决策
    """
    try:
        # 读取告警文件
        with open(alert_file, 'r', encoding='utf-8') as f:
            alert = json.load(f)
        
        # 初始化分析器
        analyzer = AIAnalyzer()
        
        # 分析告警
        console.print("\n[bold blue]正在分析告警...[/bold blue]")
        result = analyzer.analyze_alert(alert)
        
        # 显示分析结果
        console.print("\n[bold green]分析结果：[/bold green]")
        console.print(Panel(Markdown(result["analysis"])))
        
        # 显示响应决策
        decision = result["response_decision"]
        console.print("\n[bold magenta]响应决策：[/bold magenta]")
        console.print(f"是否执行响应动作: {'是' if decision['should_respond'] else '否'}")
        console.print(f"决策原因: {decision['reason']}")
        
        # 根据决策执行响应动作
        source_ip = alert["event"]["source"]["ip"]
        if force_execute or decision["should_respond"]:
            console.print(f"\n[bold red]正在执行响应动作：封锁IP {source_ip}[/bold red]")
            response = analyzer.execute_response(source_ip)
            console.print(json.dumps(response, indent=2, ensure_ascii=False))
        else:
            console.print("\n[bold yellow]根据AI分析，不建议执行响应动作[/bold yellow]")
            
    except Exception as e:
        console.print(f"[bold red]错误：{str(e)}[/bold red]")

@app.command()
def list_blocked():
    """
    列出当前被封锁的IP地址
    
    显示所有当前被防火墙封锁的IP地址及其详细信息
    """
    analyzer = AIAnalyzer()
    blocked_ips = analyzer.response_actions.get_blocked_ips()
    console.print("\n[bold blue]当前被封锁的IP地址：[/bold blue]")
    console.print(json.dumps(blocked_ips, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    app() 