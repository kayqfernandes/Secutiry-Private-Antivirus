"""Background scan orchestration, isolated from Tk widgets."""
from __future__ import annotations
import threading
import uuid
from ..core.models import ScanSummary
from ..integrations.defender import defender_scan
from ..integrations.startup import startup_entries

class ScanController:
    def __init__(self,app):self.app=app
    def start(self,roots,key,ask_defender=False,run_id=None):
        run_id=run_id or uuid.uuid4().hex
        threading.Thread(target=self._worker,args=(roots,key,ask_defender,run_id),daemon=True).start()
        return run_id
    def _run_defender(self,scan_type,path=None,run_id=None):
        app=self.app
        request_id=uuid.uuid4().hex[:12]
        started=("defender_started",request_id,scan_type,path)
        app.events.put(started if run_id is None else (*started,run_id))
        try:
            detections=defender_scan(scan_type,path)
            results=("defender_results",request_id,scan_type,path,detections)
            app.events.put(results if run_id is None else (*results,run_id))
        except Exception as e:
            error=("defender_error",request_id,str(e))
            app.events.put(error if run_id is None else (*error,run_id))
        return request_id
    def _audit(self,event,details,run_id=None):
        try:
            self.app.scanner.audit(event,details)
        except OSError as exc:
            warning=("audit_warning",str(exc))
            self.app.events.put(warning if run_id is None else (*warning,run_id))
    def _worker(self,roots,key,ask_defender=False,run_id=None):
        app=self.app
        run_id=run_id or uuid.uuid4().hex
        found=[];count=0;cancelled=False;summary=ScanSummary()
        try:
            if ask_defender:
                threading.Thread(target=self._run_defender,args=("FullScan",None,run_id),daemon=True).start()
            startup=startup_entries()
            summary.startup_items_found=len(startup.entries);summary.startup_errors=len(startup.errors)
            self._audit("scan_started",{"run_id":run_id,"roots":roots,"online_hash_lookup":bool(key),"startup_items_found":len(startup.entries),"startup_errors":len(startup.errors)},run_id)
            for entry in startup.entries:app.events.put(("startup",run_id,entry))
            found,count,cancelled,scan_summary=app.scanner.scan(roots,lambda f,n:app.events.put(("finding",run_id,f,n)),app.cancel_event,key)
            scan_summary.startup_items_found=len(startup.entries);scan_summary.startup_errors=len(startup.errors);summary=scan_summary
        except Exception as exc:
            app.events.put(("error",run_id,f"Falha durante a busca: {exc}"))
        finally:
            self._audit("scan_finished",{"run_id":run_id,"files":count,"findings":len(found),"cancelled":cancelled,"summary":summary.__dict__},run_id)
            app.events.put(("done",run_id,count,cancelled,summary))

