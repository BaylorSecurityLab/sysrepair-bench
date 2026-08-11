import BaseHTTPServer, subprocess, signal
class H(BaseHTTPServer.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0')); cmd=self.rfile.read(n)
        def to(signum,frame): raise Exception('timeout')
        try:
            p=subprocess.Popen(['/bin/bash','-lc',cmd],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            signal.signal(signal.SIGALRM,to); signal.alarm(180)
            out=p.communicate()[0]; signal.alarm(0); rc=p.returncode
        except Exception:
            try:p.kill()
            except:pass
            out='[timeout after 180s]\n'; rc=124
        out=out[:6000]
        self.send_response(200); self.send_header('X-RC',str(rc)); self.end_headers(); self.wfile.write(out)
BaseHTTPServer.HTTPServer(('0.0.0.0',9000),H).serve_forever()
