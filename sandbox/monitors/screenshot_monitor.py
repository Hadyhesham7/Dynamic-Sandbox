"""
screenshot_monitor.py - Background desktop screenshot capture
===========================================================
Captures periodic screenshots of the desktop while the sample runs.
Saved to reports/artifacts/screenshots/
"""

import os
import time
import threading

class ScreenshotMonitor:
    def __init__(self, output_dir, interval=3.0):
        self.output_dir = output_dir
        self.interval = interval
        self.running = False
        self.thread = None
        self.screenshots_taken = []
        
        os.makedirs(self.output_dir, exist_ok=True)

        try:
            from PIL import ImageGrab
            self._grab = ImageGrab.grab
            self.available = True
        except ImportError:
            print("[SCREENSHOT] WARNING: 'Pillow' is not installed. Screenshots are disabled.")
            print("[SCREENSHOT] Run 'pip install Pillow' to enable.")
            self.available = False

    def start(self):
        if not self.available:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

    def _capture_loop(self):
        count = 1
        while self.running:
            try:
                img = self._grab()
                timestamp = int(time.time() * 1000)
                filename = f"screenshot_{count:03d}_{timestamp}.jpg"
                filepath = os.path.join(self.output_dir, filename)
                
                # Resize slightly to save space and save as JPEG
                # 1920x1080 -> 1280x720 is usually good enough for reports
                img.thumbnail((1280, 720))
                img.save(filepath, "JPEG", quality=75)
                
                self.screenshots_taken.append(filepath)
                count += 1
            except Exception as e:
                pass # Ignore grab errors (e.g., locked screen)
            
            # Wait for next interval
            start_wait = time.time()
            while self.running and (time.time() - start_wait) < self.interval:
                time.sleep(0.5)

    def get_summary(self):
        """Return a summary of captured screenshots"""
        return {
            "count": len(self.screenshots_taken),
            "files": [os.path.basename(f) for f in self.screenshots_taken],
            "directory": self.output_dir
        }
