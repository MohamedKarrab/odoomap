import time
from rich.console import Console
from rich.live import Live
from rich.text import Text

console = Console()

class BruteDisplay:
    def __init__(self, total):
        self.total = total
        self.attempts = 0
        self.errors = 0
        self.successes = []
        self.start_time = time.time()
        self.attempt_times = []  # Sliding window of last 5 attempt timestamps
        self.window_size = 5
        self.live = Live(self._render("", 0, 0), console=console, refresh_per_second=10, auto_refresh=True,
    transient=False)
        self.live.__enter__()

    def _render(self, current_try, attempts, errors):
        elapsed = time.time() - self.start_time
        
        # Calculate rate based on sliding window of last N attempts
        if len(self.attempt_times) >= 2:
            time_span = self.attempt_times[-1] - self.attempt_times[0]
            rps = (len(self.attempt_times) - 1) / time_span if time_span > 0 else 0
        else:
            rps = 0
            
        percent = (attempts / self.total * 100) if self.total > 0 else 0

        # build manually with Text to avoid auto coloring
        text = Text()
        text.append(f"{current_try}\n", style="white")
        text.append(f"{attempts}", style="white")
        text.append(f"/{self.total} ", style="white")
        text.append(f"({percent:.1f}%)", style="yellow")
        text.append(" | ")
        text.append(f"{rps:.2f}", style="bold magenta")
        text.append(" req/s | ")
        text.append(f"{int(elapsed)}s", style="bold green")
        text.append(" elapsed | errors: ")
        text.append(f"{errors}", style="bold red")

        return text

    def update(self, current_try):
        self.attempts += 1
        current_time = time.time()
        self.attempt_times.append(current_time)
        
        # Keep only last N attempts in the window
        if len(self.attempt_times) > self.window_size:
            self.attempt_times.pop(0)
            
        self.live.update(self._render(current_try, self.attempts, self.errors))

    def add_success(self, msg):
        self.successes.append(msg)
        console.print(f"[green] [+][/green] {msg}")

    def add_error(self, msg=""):
        self.errors += 1
        if msg:
            console.print(f"[red]ERROR:[/red] {msg}")

    def stop(self):
        self.live.__exit__(None, None, None)
        elapsed = time.time() - self.start_time
        
        # Calculate final rate based on sliding window
        if len(self.attempt_times) >= 2:
            time_span = self.attempt_times[-1] - self.attempt_times[0]
            rps = (len(self.attempt_times) - 1) / time_span if time_span > 0 else 0
        else:
            rps = 0
            
        console.print(
            f"\n",
            f"[white]Process complete:[/white]", end=""
        )

        if len(self.successes) > 0:
            console.print(f"[green] Success={len(self.successes)}")
        else:
            console.print(f"[red] Success=0")
