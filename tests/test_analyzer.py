import hashlib, json, os, queue, sys, tempfile, threading, unittest
from pathlib import Path
from app import classify, sha256_file
from src.security_analyzer.app.window import App
from resource.designer import App as DesignerApp
from src.security_analyzer.app.controllers import ScanController
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from src.security_analyzer.core.models import Finding, ScanSummary, file_identity
from src.security_analyzer.core.scanner import Scanner
from src.security_analyzer.core import static_inspection as static_inspection_module
from src.security_analyzer.core.static_inspection import inspect_source_file
from src.security_analyzer.integrations import defender as defender_module
from src.security_analyzer.integrations import drives as drives_module
from src.security_analyzer.integrations import reputation as reputation_module
from src.security_analyzer.integrations import startup as startup_module
from src.security_analyzer.integrations.startup import StartupResult
from src.security_analyzer.remediation import registry as registry_module
from src.security_analyzer.remediation.file_actions import delete_file, delete_temp_file
from src.security_analyzer.remediation.quarantine import quarantine_file, inspect_quarantine_entry, restore_file
from src.security_analyzer.remediation import quarantine as quarantine_module
from src.security_analyzer.selfcheck import run as run_selfcheck
from src.security_analyzer.storage.reports import build_report
from src.security_analyzer.storage import audit as audit_module

class FakeTree:
    def __init__(self, columns=()):
        self.columns={name:index for index,name in enumerate(columns)}
        self.rows={};self.order=[];self.selected=();self.ypos=0.0;self.xpos=0.0
    def insert(self,_parent,index,iid,values=(),tags=()):
        self.rows[iid]=tuple(values);self.order.append(iid)
    def exists(self,iid):
        return iid in self.rows
    def delete(self,*items):
        for iid in items:
            self.rows.pop(iid,None)
            if iid in self.order:self.order.remove(iid)
            self.selection_remove(iid)
    def get_children(self,_parent=""):
        return tuple(self.order)
    def move(self,iid,_parent,index):
        self.order.remove(iid);self.order.insert(index,iid)
    def set(self,iid,column):
        return self.rows[iid][self.columns[column]]
    def selection(self):
        return self.selected
    def selection_set(self,items):
        self.selected=tuple(items)
    def selection_remove(self,*items):
        self.selected=tuple(iid for iid in self.selected if iid not in items)
    def yview(self):
        return self.ypos,1.0
    def xview(self):
        return self.xpos,1.0
    def yview_moveto(self,value):
        self.ypos=value
    def xview_moveto(self,value):
        self.xpos=value

class AnalyzerTests(unittest.TestCase):
    @staticmethod
    def _filter_app(**overrides):
        values={"filter_risk":"Todas"}
        values.update(overrides)
        app=DesignerApp.__new__(DesignerApp)
        for name,value in values.items():
            setattr(app,name,SimpleNamespace(get=lambda current=value:current))
        return app

    def test_classification_filter_does_not_change_technical_classification(self):
        finding=Finding(r"C:\Review\helper.py",kind="Executável",signature="Não assinada",risk="Suspeito")
        app=self._filter_app(filter_risk="Suspeito")
        self.assertTrue(DesignerApp._matches_result_filters(app,finding))
        app.filter_risk=SimpleNamespace(get=lambda:"Alto risco")
        self.assertFalse(DesignerApp._matches_result_filters(app,finding))
        self.assertEqual(finding.risk,"Suspeito")

    def test_result_risk_filter_includes_explicit_manual_labels(self):
        dangerous=Finding("danger.exe",risk="Inconclusivo",manual_classification="Perigoso")
        low=Finding("review.exe",risk="Suspeito",manual_classification="Baixo risco")
        self.assertTrue(DesignerApp._matches_result_filters(self._filter_app(filter_risk="Perigoso"),dangerous))
        self.assertTrue(DesignerApp._matches_result_filters(self._filter_app(filter_risk="Baixo risco"),low))
        self.assertEqual((dangerous.risk,low.risk),("Inconclusivo","Suspeito"))

    def test_file_table_displays_name_while_details_keep_full_path(self):
        path=r"C:\Program Files\Vendor\deep\helper.exe"
        self.assertEqual(DesignerApp._display_path(path),"helper.exe")

    def test_sorted_tree_inserts_new_finding_in_active_order(self):
        tree=FakeTree(("size",));small=Finding("small",size_bytes=10);large=Finding("large",size_bytes=30);medium=Finding("medium",size_bytes=20)
        app=DesignerApp.__new__(DesignerApp)
        app.by_iid={str(id(item)):item for item in (small,large,medium)}
        app.tree_sort_state={tree:("size",False)}
        for finding in (small,large):tree.insert("","end",iid=str(id(finding)),values=(finding.size_bytes,))
        tree.insert("","end",iid=str(id(medium)),values=(medium.size_bytes,))
        DesignerApp._insert_sorted(app,tree,str(id(medium)))
        self.assertEqual([app.by_iid[iid].path for iid in tree.get_children()],["small","medium","large"])

    def test_tree_refresh_keeps_visible_selection_and_scroll_position(self):
        tree=FakeTree();tree.insert("","end",iid="visible");tree.selected=("visible",);tree.ypos=.4
        app=DesignerApp.__new__(DesignerApp);app.result_tree=tree;app.danger_tree=FakeTree();app.temp_tree=FakeTree()
        app.result_detail=object();app.danger_detail=object();app.temp_detail=object()
        app.show_detail=MagicMock();app._set_detail=MagicMock()
        DesignerApp._restore_tree_state(app,tree,(("visible",),.4))
        self.assertEqual(tree.selection(),("visible",));self.assertEqual(tree.ypos,.4)
        app.show_detail.assert_called_once_with(tree)

    def test_tree_refresh_clears_details_when_selection_is_filtered_out(self):
        tree=FakeTree();tree.selected=("removed",)
        app=DesignerApp.__new__(DesignerApp);app.result_tree=tree;app.danger_tree=FakeTree();app.temp_tree=FakeTree()
        app.result_detail=object();app.danger_detail=object();app.temp_detail=object()
        app.show_detail=MagicMock();app._set_detail=MagicMock()
        DesignerApp._restore_tree_state(app,tree,(("removed",),.3))
        self.assertEqual(tree.selection(),())
        app._set_detail.assert_called_once_with(app.result_detail,"Selecione um item para ver os detalhes.")

    def test_large_result_rebuild_yields_between_bounded_ui_batches(self):
        app=self._filter_app()
        app.findings=[Finding(f"item-{index}.txt",size_bytes=index) for index in range(501)]
        app.result_tree=FakeTree(("risk","size","kind","signature","modified","path"))
        app.danger_tree=FakeTree(("risk","size","kind","signature","modified","path"))
        app.temp_tree=FakeTree(("risk","size","kind","signature","modified","path"))
        app.result_detail=object();app.danger_detail=object();app.temp_detail=object()
        app.tree_sort_state={};app._rebuild_generation=0;app._batch_rebuilding=False
        app.filter_count=SimpleNamespace(configure=MagicMock())
        app.after_idle=MagicMock();app.after=MagicMock();app._set_detail=MagicMock()
        app.show_detail=MagicMock();app.refresh_quarantine=MagicMock()
        scheduled=[]
        app.after_idle.side_effect=lambda callback,*args:scheduled.append((callback,args))
        app.after.side_effect=lambda _delay,callback,*args:scheduled.append((callback,args))
        with patch("resource.designer.is_executable",return_value=False), \
             patch("resource.designer.is_temp_candidate",return_value=False):
            DesignerApp._rebuild(app)
            self.assertEqual(len(app.result_tree.get_children()),0)
            callback,args=scheduled.pop(0);callback(*args)
        self.assertEqual(len(app.result_tree.get_children()),250)
        self.assertEqual(len(scheduled),1)
        self.assertEqual(scheduled[0][1],(250,))

    def test_volume_inventory_reports_capacity_and_unavailable_status_without_scanning(self):
        usage=SimpleNamespace(total=5000,free=3000)
        with patch.object(drives_module,"drives",return_value=["C:\\","E:\\"]), \
             patch.object(drives_module,"_volume_label",side_effect=["System","USB"]), \
             patch.object(drives_module,"_drive_type",side_effect=["Fixo","Removível"]), \
             patch.object(drives_module.shutil,"disk_usage",side_effect=[usage,PermissionError("mídia indisponível")]):
            volumes=drives_module.enumerate_volumes()
        self.assertEqual(len(volumes),2)
        self.assertEqual((volumes[0].root,volumes[0].label,volumes[0].drive_type),("C:\\","System","Fixo"))
        self.assertEqual((volumes[0].total_bytes,volumes[0].free_bytes,volumes[0].status),(5000,3000,"Disponível"))
        self.assertEqual((volumes[1].root,volumes[1].label,volumes[1].drive_type),("E:\\","USB","Removível"))
        self.assertEqual(volumes[1].status,"Indisponível")
        self.assertIn("mídia indisponível",volumes[1].error)

    def test_static_source_inspection_reports_signals_without_running_content(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"sample.py"
            path.write_text("# review only\nexec('text')\nsubprocess.run(['tool'])\n",encoding="utf-8")
            result=inspect_source_file(str(path))
            self.assertEqual(result["text"].replace("\r\n","\n"),path.read_text(encoding="utf-8"))
            self.assertIn({"label":"Execução dinâmica","line":2},result["indicators"])
            self.assertIn({"label":"Criação ou execução de processos","line":3},result["indicators"])
            self.assertFalse(result["truncated"])

    def test_static_source_inspection_rejects_binary_and_unknown_extensions(self):
        with tempfile.TemporaryDirectory() as folder:
            binary=Path(folder)/"sample.py";binary.write_bytes(b"print('x')\x00\x01")
            with self.assertRaisesRegex(OSError,"binário"):
                inspect_source_file(str(binary))
            executable=Path(folder)/"sample.exe";executable.write_bytes(b"MZ")
            with self.assertRaisesRegex(OSError,"extensões"):
                inspect_source_file(str(executable))

    def test_static_source_inspection_limits_large_file_read(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"large.js";path.write_bytes(b"a"*32)
            with patch.object(static_inspection_module,"MAX_INSPECTION_BYTES",8):
                result=inspect_source_file(str(path))
            self.assertTrue(result["truncated"])
            self.assertEqual(len(result["text"]),8)

    def test_sha256_matches_known_content(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"sample.txt"; path.write_bytes(b"hello")
            self.assertEqual(sha256_file(str(path)), hashlib.sha256(b"hello").hexdigest())
    def test_defender_detection_is_high_risk(self):
        risk,reason,_=classify(r"C:\Users\A\sample.exe", "Válida", defender_hit=True)
        self.assertEqual(risk,"Alto risco"); self.assertIn("Defender",reason)
    def test_unsigned_executable_is_suspicious_not_certain(self):
        risk,reason,_=classify(r"C:\Users\A\sample.exe", "Não assinada")
        self.assertEqual(risk,"Suspeito"); self.assertIn("não confirma malware",reason)
    def test_signed_executable_is_only_low_risk(self):
        risk,reason,_=classify(r"C:\Program Files\sample.exe", "Válida")
        self.assertEqual(risk,"Baixo risco"); self.assertIn("não garante",reason)
    def test_non_executable_without_signal_is_inconclusive(self):
        self.assertEqual(classify(r"C:\Users\A\notes.txt")[0],"Inconclusivo")
    def test_failed_hash_is_inconclusive(self):
        self.assertEqual(classify(r"C:\Users\A\sample.exe",hash_ok=False)[0],"Inconclusivo")

    def test_manual_decision_does_not_erase_technical_detection(self):
        finding=Finding(r"C:\sample.exe",risk="Alto risco",manual_classification="Baixo risco")
        report=build_report([finding])
        self.assertEqual(finding.risk,"Alto risco")
        self.assertEqual(report["summary"]["Alto risco"],1)
        self.assertEqual(report["summary"]["Baixo risco"],0)
        self.assertEqual(report["manual_decisions"]["Baixo risco"],1)
        self.assertNotIn("file_identity",report["findings"][0])

    def test_report_includes_scan_coverage_summary(self):
        summary=ScanSummary(files_seen=7,unreadable_files=1,inaccessible_directories=2)
        report=build_report([Finding("sample.txt")],summary)
        self.assertEqual(report["scan_summary"]["files_seen"],7)
        self.assertEqual(report["scan_summary"]["inaccessible_directories"],2)

    def test_scan_report_does_not_start_overlapping_local_run(self):
        fake=SimpleNamespace(scan_active=True,status=MagicMock())
        App.start_scan(fake,["unused"])
        fake.status.configure.assert_called_once_with(text="Uma busca já está em andamento. Aguarde ou cancele antes de iniciar outra.")

    def test_poll_ignores_scan_events_from_another_run(self):
        events=queue.Queue()
        events.put(("finding","older-run",Finding("stale.txt"),1))
        events.put(("done","older-run",1,False,ScanSummary(files_seen=1)))
        events.put(("defender_results","old-request","FullScan",None,[],"older-run"))
        fake=SimpleNamespace(events=events,scan_request_id="current-run",after=MagicMock(),_poll=MagicMock())
        App._poll(fake)
        self.assertTrue(events.empty())
        fake.after.assert_called_once_with(100,fake._poll)

    def test_poll_accepts_completion_for_current_scan_request(self):
        events=queue.Queue();summary=ScanSummary(files_seen=3)
        events.put(("done","current-run",3,False,summary))
        fake=SimpleNamespace(
            events=events,scan_request_id="current-run",after=MagicMock(),_poll=MagicMock(),
            progress=MagicMock(),_set_scan_active=MagicMock(),_rebuild=MagicMock(),
            scan_summary=None,status=SimpleNamespace(configure=MagicMock()),
        )
        App._poll(fake)
        self.assertIs(fake.scan_summary,summary)
        fake._set_scan_active.assert_called_once_with(False)

    def test_controller_tags_findings_and_completion_with_same_run_id(self):
        events=MagicMock();finding=Finding("sample.txt");summary=ScanSummary(files_seen=1)
        def scan(_roots,callback,_cancel,_key):
            callback(finding,1)
            return [finding],1,False,summary
        fake=SimpleNamespace(
            scanner=SimpleNamespace(audit=MagicMock(),scan=scan),events=events,
            cancel_event=threading.Event(),
        )
        with patch("src.security_analyzer.app.controllers.startup_entries",return_value=StartupResult()):
            ScanController(fake)._worker(["root"],"",False,"scan-42")
        queued=[call.args[0] for call in events.put.call_args_list]
        self.assertIn(("finding","scan-42",finding,1),queued)
        self.assertIn(("done","scan-42",1,False,summary),queued)

    def test_controller_reports_audit_failure_without_raising(self):
        fake=SimpleNamespace(scanner=SimpleNamespace(audit=MagicMock(side_effect=OSError("disk full"))),events=MagicMock())
        ScanController(fake)._audit("scan_started",{})
        fake.events.put.assert_called_once_with(("audit_warning","disk full"))

    def test_controller_finishes_scan_even_when_audit_writes_fail(self):
        events=MagicMock()
        summary=ScanSummary(files_seen=2)
        scanner=SimpleNamespace(audit=MagicMock(side_effect=OSError("disk full")),scan=MagicMock(return_value=([],2,False,summary)))
        fake=SimpleNamespace(scanner=scanner,events=events,cancel_event=threading.Event())
        with patch("src.security_analyzer.app.controllers.startup_entries",return_value=StartupResult()):
            ScanController(fake)._worker(["root"],"",False,"test-run")
        self.assertTrue(any(call.args[0][0]=="done" for call in events.put.call_args_list))
        self.assertTrue(any(call.args[0][1]=="test-run" for call in events.put.call_args_list if call.args[0][0]=="done"))

    def test_scanner_checks_all_extensions_across_selected_roots(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second, tempfile.TemporaryDirectory() as logs:
            paths=[Path(first)/"notes.txt",Path(first)/"script.py",Path(second)/"client.js",Path(second)/"tool.exe"]
            for path in paths:path.write_text("sample",encoding="utf-8")
            with patch("src.security_analyzer.core.scanner.signature_status",return_value="Não assinada"):
                findings,count,cancelled,_summary=Scanner(Path(logs)/"audit.jsonl").scan(
                    [first,second],lambda *_:None,threading.Event())
            self.assertEqual(count,4)
            self.assertFalse(cancelled)
            self.assertEqual({Path(f.path).name for f in findings},{path.name for path in paths})

    def test_scanner_captures_size_and_modification_time_for_result_filters(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as logs:
            path=Path(root)/"metadata.txt";path.write_bytes(b"metadata")
            expected=path.stat()
            findings,_,_,_=Scanner(Path(logs)/"audit.jsonl").scan([root],lambda *_:None,threading.Event())
        self.assertEqual(findings[0].size_bytes,expected.st_size)
        self.assertEqual(findings[0].modified_time,expected.st_mtime)

    def test_startup_scan_reports_registry_access_failures(self):
        with tempfile.TemporaryDirectory() as folder:
            fake_os=SimpleNamespace(name="nt",environ={"APPDATA":folder,"PROGRAMDATA":folder})
            fake_winreg=SimpleNamespace(HKEY_CURRENT_USER=object(),HKEY_LOCAL_MACHINE=object(),OpenKey=MagicMock(side_effect=PermissionError("access denied")))
            with patch.object(startup_module,"os",fake_os),patch.dict(sys.modules,{"winreg":fake_winreg}):
                result=startup_module.startup_entries()
        self.assertEqual(result.entries,[])
        self.assertEqual(len(result.errors),3)

    def test_defender_requests_have_distinct_correlation_ids(self):
        events=MagicMock();fake=SimpleNamespace(events=events)
        with patch("src.security_analyzer.app.controllers.defender_scan",return_value=[]):
            first=ScanController(fake)._run_defender("CustomScan",r"C:\First")
            second=ScanController(fake)._run_defender("CustomScan",r"C:\Second")
        self.assertNotEqual(first,second)
        queued=[call.args[0] for call in events.put.call_args_list]
        self.assertIn(("defender_results",first,"CustomScan",r"C:\First",[]),queued)
        self.assertIn(("defender_results",second,"CustomScan",r"C:\Second",[]),queued)

    def test_defender_scan_started_by_local_run_keeps_run_id(self):
        events=MagicMock();fake=SimpleNamespace(events=events)
        with patch("src.security_analyzer.app.controllers.defender_scan",return_value=[]):
            ScanController(fake)._run_defender("FullScan",run_id="scan-42")
        queued=[call.args[0] for call in events.put.call_args_list]
        self.assertEqual(queued[0][-1],"scan-42")
        self.assertEqual(queued[1][-1],"scan-42")

    def test_audit_log_rotates_with_one_bounded_backup(self):
        with tempfile.TemporaryDirectory() as folder:
            audit=Path(folder)/"audit.jsonl"
            with patch.object(audit_module,"MAX_AUDIT_BYTES",128):
                for index in range(8):
                    audit_module.write_audit_event(audit,"event",{"index":index,"path":"x"*24})
            backup=audit.with_name(audit.name+".1")
            self.assertTrue(audit.exists());self.assertTrue(backup.exists())
            self.assertLessEqual(audit.stat().st_size,256)
            self.assertLessEqual(backup.stat().st_size,256)

    def test_scanner_skips_reparse_entries(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as logs:
            keep=Path(root)/"keep.txt";skip=Path(root)/"skip.txt"
            keep.write_text("keep",encoding="utf-8");skip.write_text("skip",encoding="utf-8")
            with patch("src.security_analyzer.core.scanner.is_link_or_reparse_point",side_effect=lambda p:Path(p).name=="skip.txt"):
                findings,count,cancelled,summary=Scanner(Path(logs)/"audit.jsonl").scan([root],lambda *_:None,threading.Event())
            self.assertEqual(count,1);self.assertEqual([Path(f.path).name for f in findings],["keep.txt"]);self.assertFalse(cancelled)
            self.assertEqual(summary.skipped_reparse_points,1)

    def test_scanner_rejects_reparse_root(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as logs:
            (Path(root)/"file.txt").write_text("x",encoding="utf-8")
            with patch("src.security_analyzer.core.scanner.is_link_or_reparse_point",return_value=True):
                findings,count,_,summary=Scanner(Path(logs)/"audit.jsonl").scan([root],lambda *_:None,threading.Event())
            self.assertEqual((findings,count),([],0))
            self.assertEqual(summary.skipped_reparse_points,1)

    def test_scanner_reports_inaccessible_file_as_inconclusive(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as logs:
            target=Path(root)/"locked.txt";target.write_text("data",encoding="utf-8")
            with patch("src.security_analyzer.core.scanner.sha256_file",side_effect=PermissionError("access denied")):
                findings,count,cancelled,summary=Scanner(Path(logs)/"audit.jsonl").scan([root],lambda *_:None,threading.Event())
            self.assertEqual(count,1);self.assertFalse(cancelled)
            self.assertEqual(findings[0].risk,"Inconclusivo")
            self.assertIn("access denied",findings[0].reasons)
            self.assertEqual(summary.unreadable_files,1)

    def test_scanner_reports_inaccessible_directories_and_unavailable_roots(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as logs:
            missing=Path(root)/"not-present"
            def walk_with_error(path,onerror,followlinks):
                onerror(PermissionError("directory denied"))
                yield path,[],[]
            with patch("src.security_analyzer.core.scanner.os.walk",side_effect=walk_with_error):
                _,_,_,summary=Scanner(Path(logs)/"audit.jsonl").scan([root,str(missing)],lambda *_:None,threading.Event())
            self.assertEqual(summary.inaccessible_directories,1)
            self.assertEqual(summary.unavailable_roots,1)

    def test_scanner_marks_file_replaced_during_analysis_inconclusive(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as logs:
            (Path(root)/"sample.txt").write_text("data",encoding="utf-8")
            with patch("src.security_analyzer.core.scanner.file_identity",side_effect=["before","after"]):
                findings,_,_,_summary=Scanner(Path(logs)/"audit.jsonl").scan([root],lambda *_:None,threading.Event())
            self.assertEqual(findings[0].risk,"Inconclusivo")
            self.assertEqual(findings[0].sha256,"")
            self.assertEqual(findings[0].file_identity,"")

    def test_scanner_honors_cancellation(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as logs:
            (Path(root)/"one.txt").write_text("1",encoding="utf-8")
            cancel=threading.Event();cancel.set()
            findings,count,cancelled,_summary=Scanner(Path(logs)/"audit.jsonl").scan([root],lambda *_:None,cancel)
            self.assertEqual((findings,count,cancelled),([],0,True))

    def test_reputation_is_opt_in_and_receives_only_hash(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as logs:
            target=Path(root)/"sample.txt";target.write_text("local content",encoding="utf-8")
            digest=hashlib.sha256(b"local content").hexdigest()
            with patch("src.security_analyzer.core.scanner.reputation_lookup",return_value="Sem detecção") as lookup:
                findings,_,_,_summary=Scanner(Path(logs)/"audit.jsonl").scan([root],lambda *_:None,threading.Event(),"session-key")
            lookup.assert_called_once_with(digest,"session-key")
            self.assertEqual(findings[0].reputation,"Sem detecção")

    def test_reputation_is_not_called_without_opt_in_key(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as logs:
            (Path(root)/"sample.txt").write_text("local",encoding="utf-8")
            with patch("src.security_analyzer.core.scanner.reputation_lookup") as lookup:
                Scanner(Path(logs)/"audit.jsonl").scan([root],lambda *_:None,threading.Event())
            lookup.assert_not_called()

    def test_packaged_selfcheck_uses_disposable_fixture(self):
        self.assertEqual(run_selfcheck(),0)

    def test_quarantine_manifest_cannot_redirect_source_outside_quarantine(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);source=base/"sample.exe";qdir=base/"Quarantine";source.write_bytes(b"sample")
            meta=quarantine_file(str(source),sha256_file(str(source)),file_identity(str(source)),qdir);manifest=qdir/(Path(meta["quarantine_path"]).stem+".json")
            saved=json.loads(manifest.read_text(encoding="utf-8"));saved["quarantine_path"]=str(base/"other.exe");manifest.write_text(json.dumps(saved),encoding="utf-8")
            with self.assertRaises(OSError):inspect_quarantine_entry(manifest,qdir)

    def test_quarantine_restore_checks_stored_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);source=base/"sample.exe";qdir=base/"Quarantine";source.write_bytes(b"sample")
            meta=quarantine_file(str(source),sha256_file(str(source)),file_identity(str(source)),qdir);stored=Path(meta["quarantine_path"]);stored.write_bytes(b"changed")
            manifest=qdir/(stored.stem+".json")
            with self.assertRaises(OSError):inspect_quarantine_entry(manifest,qdir)

    def test_quarantine_restore_rejects_reparse_ancestor(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);source=base/"sample.exe";qdir=base/"Quarantine";source.write_bytes(b"sample")
            meta=quarantine_file(str(source),sha256_file(str(source)),file_identity(str(source)),qdir)
            stored=Path(meta["quarantine_path"]);manifest=qdir/(stored.stem+".json")
            junction=base/"junction";junction.mkdir()
            data=json.loads(manifest.read_text(encoding="utf-8"));data["original_path"]=str(junction/"missing"/"restored.exe")
            manifest.write_text(json.dumps(data),encoding="utf-8")
            with patch.object(quarantine_module,"is_link_or_reparse_point",side_effect=lambda path:Path(path)==junction):
                with self.assertRaisesRegex(OSError,"ponto de nova análise"):
                    inspect_quarantine_entry(manifest,qdir)

    def test_quarantine_restores_validated_file_and_removes_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);source=base/"sample.exe";qdir=base/"Quarantine";source.write_bytes(b"sample")
            meta=quarantine_file(str(source),sha256_file(str(source)),file_identity(str(source)),qdir)
            manifest=qdir/(Path(meta["quarantine_path"]).stem+".json")
            restored=restore_file(manifest,qdir)
            self.assertEqual(source.read_bytes(),b"sample")
            self.assertFalse(manifest.exists())
            self.assertEqual(restored["sha256"],hashlib.sha256(b"sample").hexdigest())

    def test_delete_refuses_file_changed_since_analysis(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/"sample.exe";target.write_bytes(b"before")
            with self.assertRaisesRegex(OSError,"mudou"):
                delete_file(str(target),hashlib.sha256(b"old content").hexdigest(),file_identity(str(target)))
            self.assertTrue(target.exists())

    def test_delete_refuses_different_file_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/"sample.exe";target.write_bytes(b"same bytes")
            digest=sha256_file(str(target))
            with self.assertRaisesRegex(OSError,"substituído"):
                delete_file(str(target),digest,"different-file-id")
            self.assertTrue(target.exists())

    def test_delete_and_quarantine_require_a_reference_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);target=base/"sample.exe";target.write_bytes(b"keep me")
            with self.assertRaisesRegex(OSError,"Hash de referência"):
                delete_file(str(target),"",file_identity(str(target)))
            with self.assertRaisesRegex(OSError,"Hash de referência"):
                delete_temp_file(str(target),"",file_identity(str(target)))
            with self.assertRaisesRegex(OSError,"Hash de referência"):
                quarantine_file(str(target),"",file_identity(str(target)),base/"Quarantine")
            self.assertTrue(target.exists())
            self.assertFalse((base/"Quarantine").exists())

    def test_temp_delete_is_limited_to_temp_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/"candidate.tmp";target.write_bytes(b"temp")
            delete_temp_file(str(target),hashlib.sha256(b"temp").hexdigest(),file_identity(str(target)))
            self.assertFalse(target.exists())

    def _mock_registry(self,values):
        key=MagicMock()
        key.__enter__.return_value=key
        def query_value(_key,name):
            for current_name,current_value in values:
                if current_name==name:return current_value,1
            raise FileNotFoundError(name)
        fake_winreg=SimpleNamespace(
            HKEY_CURRENT_USER=object(),HKEY_LOCAL_MACHINE=object(),
            KEY_QUERY_VALUE=1,KEY_SET_VALUE=2,
            OpenKey=MagicMock(return_value=key),QueryInfoKey=MagicMock(return_value=(0,len(values),0)),
            EnumValue=MagicMock(side_effect=lambda _key,index:(values[index][0],values[index][1],1)),
            QueryValueEx=MagicMock(side_effect=query_value),
            DeleteValue=MagicMock(),
        )
        fake_os=SimpleNamespace(name="nt",path=os.path,normcase=os.path.normcase,abspath=os.path.abspath)
        return key,fake_winreg,fake_os

    def test_registry_inspection_matches_only_full_file_path(self):
        target=str(Path("C:/Users/Test/app.exe"))
        key,winreg,fake_os=self._mock_registry([
            ("target",f'"{target}" --run'),("similar",target+".backup")
        ])
        with patch.object(registry_module,"os",fake_os),patch.dict(sys.modules,{"winreg":winreg}):
            matches,errors=registry_module.matching_startup_values(target)
        self.assertEqual(len(matches),3);self.assertTrue(all(item.name=="target" for item in matches));self.assertEqual(errors,[])
        winreg.DeleteValue.assert_not_called()

    def test_registry_removal_is_scoped_to_matching_value_and_reports_failure(self):
        target="C:\\Users\\Test\\app.exe"
        key,winreg,fake_os=self._mock_registry([("target",target)])
        reviewed=[]
        with patch.object(registry_module,"os",fake_os),patch.dict(sys.modules,{"winreg":winreg}):
            reviewed,_=registry_module.matching_startup_values(target)
        winreg.DeleteValue.side_effect=PermissionError("access denied")
        with patch.object(registry_module,"os",fake_os),patch.dict(sys.modules,{"winreg":winreg}):
            matches,errors=registry_module.matching_startup_values(target,remove=True,reviewed_values=reviewed)
        self.assertEqual(len(matches),0)
        self.assertEqual(len(errors),3)
        self.assertTrue(all("access denied" in error for error in errors))

    def test_registry_does_not_remove_value_changed_after_confirmation(self):
        target="C:\\Users\\Test\\app.exe"
        _,winreg,fake_os=self._mock_registry([("target",target)])
        with patch.object(registry_module,"os",fake_os),patch.dict(sys.modules,{"winreg":winreg}):
            reviewed,_=registry_module.matching_startup_values(target)
        winreg.QueryValueEx.side_effect=lambda _key,_name:(target+".changed",1)
        with patch.object(registry_module,"os",fake_os),patch.dict(sys.modules,{"winreg":winreg}):
            removed,errors=registry_module.matching_startup_values(target,remove=True,reviewed_values=reviewed)
        self.assertEqual(removed,[])
        self.assertEqual(len(errors),3)
        winreg.DeleteValue.assert_not_called()

    def test_registry_does_not_remove_value_when_type_changed(self):
        target="C:\\Users\\Test\\app.exe"
        _,winreg,fake_os=self._mock_registry([("target",target)])
        with patch.object(registry_module,"os",fake_os),patch.dict(sys.modules,{"winreg":winreg}):
            reviewed,_=registry_module.matching_startup_values(target)
        winreg.QueryValueEx.side_effect=lambda _key,_name:(target,2)
        with patch.object(registry_module,"os",fake_os),patch.dict(sys.modules,{"winreg":winreg}):
            removed,errors=registry_module.matching_startup_values(target,remove=True,reviewed_values=reviewed)
        self.assertEqual(removed,[])
        self.assertEqual(len(errors),3)
        winreg.DeleteValue.assert_not_called()

    def test_defender_results_are_filtered_to_new_detection_window(self):
        payload='[{"detection_id":"d-2","detected_at":"2026-10-25T10:00:00Z","resources":["C:\\\\bad.exe"]}]'
        with patch.object(defender_module,"powershell",return_value=payload) as run:
            results=defender_module.defender_scan("FullScan")
        command=run.call_args.args[0]
        self.assertIn("-AsJob",command)
        self.assertIn("$_.DetectionID -notin $before",command)
        self.assertIn("$_.InitialDetectionTime -ge $scanStarted",command)
        self.assertEqual(results[0]["detection_id"],"d-2")

if __name__ == "__main__": unittest.main()

