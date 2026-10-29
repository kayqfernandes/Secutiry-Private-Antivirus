"""Tkinter window and user interaction for the security analyzer."""
from __future__ import annotations
import json, os, queue, threading, uuid
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from ..core.models import APP_NAME, Finding, ScanSummary, is_executable, is_temp_candidate, temp_roots
from ..core.scanner import Scanner
from ..integrations.drives import drives
from ..integrations.startup import startup_entries
from ..remediation.registry import matching_startup_values
from ..remediation.quarantine import quarantine_file, inspect_quarantine_entry, restore_file
from ..remediation.file_actions import delete_file, delete_temp_file
from ..storage.reports import build_report, write_report
from .controllers import ScanController

class App(tk.Tk):
    COLORS={"Perigoso":"#ff5c70","Alto risco":"#ff5c70","Suspeito":"#ffbd4a","Baixo risco":"#68d6a5","Inconclusivo":"#a9b5c7"}
    def __init__(self):
        super().__init__();self.title(APP_NAME);self.geometry("1180x760");self.minsize(900,620);self.configure(bg="#11151d")
        base=Path(os.environ.get("LOCALAPPDATA",str(Path.home())))/"PersonalSecurityAnalyzer";self.quarantine_dir=base/"Quarantine";self.events=queue.Queue();self.cancel_event=threading.Event();self.scanner=Scanner(base/"audit.jsonl");self.scan_controller=ScanController(self);self.findings=[];self.by_iid={};self.defender_detection_ids=set();self.scan_active=False;self.scan_request_id=None;self.scan_summary=ScanSummary();self._style();self._layout();self.after(100,self._poll)
    def _style(self):
        s=ttk.Style(self);s.theme_use("clam");s.configure(".",background="#11151d",foreground="#e7ebf2",fieldbackground="#1a2130",bordercolor="#293346",font=("Segoe UI",10));s.configure("TFrame",background="#11151d");s.configure("TLabel",background="#11151d",foreground="#e7ebf2");s.configure("Title.TLabel",font=("Segoe UI",20,"bold"));s.configure("Muted.TLabel",foreground="#9aa7ba");s.configure("TButton",background="#263348",foreground="#f5f7fa",padding=8);s.map("TButton",background=[("active","#354866")]);s.configure("Treeview",background="#171e29",fieldbackground="#171e29",foreground="#e7ebf2",rowheight=28);s.configure("Treeview.Heading",background="#263348",foreground="#e7ebf2");s.map("Treeview",background=[("selected","#31527b")])
    def _layout(self):
        top=ttk.Frame(self,padding=18);top.pack(fill="x");ttk.Label(top,text=APP_NAME,style="Title.TLabel").pack(anchor="w");ttk.Label(top,text="Análise somente de leitura até você escolher uma ação • Nenhum item é executado",style="Muted.TLabel").pack(anchor="w",pady=(4,12))
        bar=ttk.Frame(top);bar.pack(fill="x")
        self.folder_button=ttk.Button(bar,text="Analisar pasta…",command=self.choose_folder);self.folder_button.pack(side="left",padx=(0,7))
        self.full_scan_button=ttk.Button(bar,text="Analisar computador",command=self.full_scan);self.full_scan_button.pack(side="left",padx=7)
        self.defender_button=ttk.Button(bar,text="Defender na pasta…",command=self.defender_folder);self.defender_button.pack(side="left",padx=7)
        self.cancel_button=ttk.Button(bar,text="Cancelar busca",command=self.cancel_scan,state="disabled");self.cancel_button.pack(side="left",padx=7)
        ttk.Button(bar,text="Salvar relatório…",command=self.save_report).pack(side="left",padx=7)
        self.online=tk.BooleanVar(value=False);ttk.Checkbutton(bar,text="Reputação online (só hashes)",variable=self.online).pack(side="left",padx=12)
        self.scan_trigger_buttons=[self.folder_button,self.full_scan_button,self.defender_button]
        stat=ttk.Frame(self,padding=(18,0,18,10));stat.pack(fill="x");self.status=ttk.Label(stat,text="Pronto.",style="Muted.TLabel");self.status.pack(side="left");self.progress=ttk.Progressbar(stat,mode="indeterminate",length=180);self.progress.pack(side="right")
        self.tabs=ttk.Notebook(self);self.tabs.pack(fill="both",expand=True,padx=18,pady=(0,12))
        self.results_tab=ttk.Frame(self.tabs,padding=10);self.danger_tab=ttk.Frame(self.tabs,padding=10);self.temp_tab=ttk.Frame(self.tabs,padding=10);self.quarantine_tab=ttk.Frame(self.tabs,padding=10)
        self.tabs.add(self.results_tab,text="Resultados");self.tabs.add(self.danger_tab,text="Apps perigosos / suspeitos");self.tabs.add(self.temp_tab,text="Candidatos temporários");self.tabs.add(self.quarantine_tab,text="Quarentena")
        self.result_tree=self._make_tree(self.results_tab);self.result_tree.bind("<<TreeviewSelect>>",lambda _e:self.show_detail(self.result_tree))
        row=ttk.Frame(self.results_tab);row.pack(fill="x",pady=8);ttk.Label(row,text="Classificação manual:").pack(side="left");self.manual_choice=tk.StringVar(value="Perigoso");ttk.Combobox(row,textvariable=self.manual_choice,values=("Perigoso","Baixo risco"),state="readonly",width=18).pack(side="left",padx=7);ttk.Button(row,text="Aplicar ao selecionado",command=self.apply_manual).pack(side="left");self.result_detail=self._detail(self.results_tab)
        self.danger_tree=self._make_tree(self.danger_tab);self.danger_tree.bind("<<TreeviewSelect>>",lambda _e:self.show_detail(self.danger_tree))
        row=ttk.Frame(self.danger_tab);row.pack(fill="x",pady=8);ttk.Button(row,text="Deixar / marcar baixo risco",command=self.mark_low).pack(side="left",padx=4);ttk.Button(row,text="Colocar em quarentena",command=self.quarantine_selected).pack(side="left",padx=4);ttk.Button(row,text="Excluir arquivo…",command=self.delete_dangerous).pack(side="left",padx=4);self.danger_detail=self._detail(self.danger_tab)
        self.temp_tree=self._make_tree(self.temp_tab);self.temp_tree.bind("<<TreeviewSelect>>",lambda _e:self.show_detail(self.temp_tree))
        row=ttk.Frame(self.temp_tab);row.pack(fill="x",pady=8);self.temp_scan_button=ttk.Button(row,text="Buscar temporários",command=self.scan_temps);self.temp_scan_button.pack(side="left",padx=4);self.scan_trigger_buttons.append(self.temp_scan_button);ttk.Button(row,text="Excluir selecionado…",command=self.delete_temp_selected).pack(side="left",padx=4);ttk.Button(row,text="Excluir todos listados…",command=self.delete_all_temps).pack(side="left",padx=4);self.temp_detail=self._detail(self.temp_tab)
        self.quarantine_tree=ttk.Treeview(self.quarantine_tab,columns=("original","stored"),show="headings",height=14);self.quarantine_tree.heading("original",text="Caminho original");self.quarantine_tree.heading("stored",text="Arquivo em quarentena");self.quarantine_tree.column("original",width=650);self.quarantine_tree.column("stored",width=350);self.quarantine_tree.pack(fill="both",expand=True);self.quarantine_tree.bind("<<TreeviewSelect>>",lambda _e:self.show_quarantine_detail())
        row=ttk.Frame(self.quarantine_tab);row.pack(fill="x",pady=8);ttk.Button(row,text="Atualizar",command=self.refresh_quarantine).pack(side="left",padx=4);ttk.Button(row,text="Restaurar selecionado…",command=self.restore_selected).pack(side="left",padx=4);self.quarantine_detail=self._detail(self.quarantine_tab);self.refresh_quarantine()
        ttk.Label(self,padding=(18,0,18,8),text="Rótulos são sinais para revisão, não prova de segurança. Temporários podem ser necessários a programas em uso.",style="Muted.TLabel").pack(anchor="w")
    def _make_tree(self,parent):
        tree=ttk.Treeview(parent,columns=("risk","kind","signature","path"),show="headings",height=12)
        for c,title,width in (("risk","Classificação",150),("kind","Tipo",110),("signature","Assinatura",140),("path","Caminho",650)):tree.heading(c,text=title);tree.column(c,width=width,anchor="w")
        for risk,color in self.COLORS.items():tree.tag_configure(risk,foreground=color)
        tree.pack(fill="both",expand=True);return tree
    def _detail(self,parent):
        box=tk.Text(parent,height=5,bg="#171e29",fg="#dce4ef",insertbackground="white",relief="flat",wrap="word",font=("Segoe UI",10));box.pack(fill="x",pady=(7,0));box.configure(state="disabled");return box
    def _set_detail(self,widget,text):
        widget.configure(state="normal");widget.delete("1.0","end");widget.insert("1.0",text);widget.configure(state="disabled")
    def _risk_text(self,f):
        if f.manual_classification:return f"{f.risk} | decisão manual: {f.manual_classification}"
        return f.risk
    def _row(self,tree,f):
        label=self._risk_text(f);tree.insert("","end",iid=str(id(f)),values=(label,f.kind,f.signature,f.path),tags=(f.risk if f.risk in self.COLORS else "Inconclusivo",))
    def _selected(self,tree):
        sel=tree.selection();return self.by_iid.get(sel[0]) if sel else None
    def _audit_after_action(self,event,details):
        try:
            self.scanner.audit(event,details)
            return ""
        except OSError as exc:
            return f"\n\nA ação foi concluída, mas o registro de auditoria não pôde ser gravado: {exc}"
    def _rebuild(self):
        self.by_iid={str(id(f)):f for f in self.findings}
        for tree in (self.result_tree,self.danger_tree,self.temp_tree):tree.delete(*tree.get_children())
        for f in self.findings:
            self._row(self.result_tree,f)
            if (f.manual_classification=="Perigoso" or f.risk in ("Alto risco","Suspeito")) and is_executable(f.path):self._row(self.danger_tree,f)
            if is_temp_candidate(f.path):self._row(self.temp_tree,f)
        self.refresh_quarantine()
    def show_detail(self,tree):
        f=self._selected(tree)
        if not f:return
        text=f"Classificação técnica: {f.risk}\nDecisão manual: {f.manual_classification or 'nenhuma'}\nOrigem: {f.source}\nMotivos técnicos: {f.reasons}\nSHA-256: {f.sha256 or 'indisponível'}\nAssinatura: {f.signature}\nReputação: {f.reputation}"
        widget={self.result_tree:self.result_detail,self.danger_tree:self.danger_detail,self.temp_tree:self.temp_detail}[tree];self._set_detail(widget,text)
    def choose_folder(self):
        folder=filedialog.askdirectory(title="Escolha a pasta para analisar")
        if folder:self.start_scan([folder])
    def full_scan(self):
        if messagebox.askyesno("Analisar computador","A análise pode demorar. O app percorrerá unidades acessíveis e tentará solicitar uma verificação ao Defender. Se não estiver disponível, continuará a análise local. Continuar?"):self.start_scan(drives(),ask_defender=True)
    def defender_folder(self):
        folder=filedialog.askdirectory(title="Escolha a pasta para o Defender verificar")
        if folder:threading.Thread(target=self._defender_only,args=(folder,),daemon=True).start()
    def _defender_only(self,folder):
        try:self.scanner.audit("defender_custom_scan_requested",{"path":folder})
        except OSError as exc:self.events.put(("audit_warning",str(exc)))
        self.scan_controller._run_defender("CustomScan",folder)
    def scan_temps(self):
        roots=temp_roots()
        if not roots:messagebox.showinfo("Temporários","Não encontrei pastas temporárias acessíveis.");return
        self.tabs.select(self.temp_tab);self.start_scan(roots)
    def _set_scan_active(self,active):
        self.scan_active=active
        for button in self.scan_trigger_buttons:button.configure(state="disabled" if active else "normal")
        self.cancel_button.configure(state="normal" if active else "disabled")
    def start_scan(self,roots,ask_defender=False):
        if self.scan_active:
            self.status.configure(text="Uma busca já está em andamento. Aguarde ou cancele antes de iniciar outra.");return
        self.scan_request_id=uuid.uuid4().hex
        self._set_scan_active(True);self.scan_summary=ScanSummary();self.cancel_event.clear();self.progress.start(12);self.status.configure(text="Buscando e analisando arquivos…");self.findings=[];self._rebuild();key=""
        if self.online.get():
            key=simpledialog.askstring("Consulta por hash","Cole sua chave VirusTotal. Apenas hashes serão enviados; a chave não é guardada.",show="*",parent=self)
            if not key:self.online.set(False)
        self.scan_controller.start(roots,key,ask_defender,run_id=self.scan_request_id)
    def cancel_scan(self):
        if self.scan_active:
            self.cancel_event.set();self.status.configure(text="Parando após o arquivo atual…")

    def _poll(self):
        try:
            while True:
                event=self.events.get_nowait();typ=event[0]
                if typ in ("finding","startup","done","error"):
                    if len(event)<2 or event[1]!=self.scan_request_id:continue
                elif typ=="audit_warning" and len(event)>2 and event[-1]!=self.scan_request_id:
                    continue
                elif typ=="defender_started" and len(event)>4 and event[-1]!=self.scan_request_id:
                    continue
                elif typ=="defender_results" and len(event)>5 and event[-1]!=self.scan_request_id:
                    continue
                elif typ=="defender_error" and len(event)>3 and event[-1]!=self.scan_request_id:
                    continue
                if typ=="finding":
                    _run_id,f,n=event[1:];self.findings.append(f);self.by_iid[str(id(f))]=f;self._row(self.result_tree,f)
                    if is_temp_candidate(f.path):self._row(self.temp_tree,f)
                    if f.risk in ("Alto risco","Suspeito") and is_executable(f.path):self._row(self.danger_tree,f)
                    self.status.configure(text=f"Analisados: {n} • Suspeitos: {sum(x.risk=='Suspeito' for x in self.findings)} • Alto risco: {sum(x.risk=='Alto risco' for x in self.findings)}")
                elif typ=="startup":
                    f=Finding(event[2],kind="Inicialização",risk="Inconclusivo",reasons="Item comum de inicialização detectado; a presença sozinha não indica ameaça.",**self._finding_metadata(event[2]));self.findings.append(f);self.by_iid[str(id(f))]=f;self._row(self.result_tree,f)
                elif typ=="done":
                    _run_id,count,cancelled,summary=event[1],event[2],event[3],event[4]
                    self.scan_summary=summary;self.progress.stop();self._set_scan_active(False);self._rebuild()
                    status=f"Concluído: {count} arquivo(s) verificado(s)"
                    if summary.unreadable_files or summary.changed_files or summary.inaccessible_directories or summary.unavailable_roots:
                        status+=f" • Não verificados: {summary.unreadable_files} arquivo(s), {summary.changed_files} alterado(s), {summary.inaccessible_directories} pasta(s) inacessível(is), {summary.unavailable_roots} origem(ns) indisponível(is)"
                    if summary.skipped_reparse_points or summary.skipped_outside_root:
                        status+=f" • Ignorados por segurança: {summary.skipped_reparse_points} links/junções e {summary.skipped_outside_root} caminho(s) fora da origem"
                    if summary.startup_items_found or summary.startup_errors:
                        status+=f" • Inicialização: {summary.startup_items_found} item(ns), {summary.startup_errors} erro(s) de leitura"
                    if cancelled:status+=" (cancelado)"
                    self.status.configure(text=status)
                elif typ=="defender_started":
                    self.status.configure(text=f"Defender: solicitação {event[1]} ({event[2]}) iniciada; resultados serão globais do dispositivo.")
                elif typ=="defender_results":
                    request_id,scan_type,folder,detections=event[1],event[2],event[3],event[4];added=0
                    for detection in detections:
                        resources=detection.get("resources",[]) if isinstance(detection,dict) else []
                        detection_id=str(detection.get("detection_id", "")) if isinstance(detection,dict) else ""
                        if detection_id and detection_id in self.defender_detection_ids:continue
                        if detection_id:self.defender_detection_ids.add(detection_id)
                        if isinstance(resources,str):resources=[resources]
                        detected_at=detection.get("detected_at","horário indisponível") if isinstance(detection,dict) else "horário indisponível"
                        for resource in resources:
                            path=str(resource)
                            if path.lower().startswith("file:_"):path=path[6:]
                            f=Finding(path,kind="Executável" if is_executable(path) else "Arquivo",risk="Alto risco",reasons=f"Detecção nova registrada globalmente no dispositivo na solicitação {request_id} ({scan_type}, {detected_at}). Não comprova relação com a pasta solicitada nem causalidade com esta varredura.",source=f"Microsoft Defender — global ({request_id})",**self._finding_metadata(path))
                            self.findings.append(f);added+=1
                    scope="global do dispositivo; não atribuída à pasta solicitada" if folder else "global do dispositivo; não comprova causalidade com a varredura"
                    self._rebuild();self.status.configure(text=f"Defender {request_id}: {added} detecção(ões) nova(s) observada(s) no período ({scope}).")
                elif typ=="defender_error":
                    self.status.configure(text=f"Defender {event[1]} indisponível ou falhou: {event[2]}. A busca local não é afetada.")
                elif typ=="audit_warning":self.status.configure(text=f"Auditoria não gravada: {event[1]}")
                elif typ=="message":self.status.configure(text=event[1])
                elif typ=="error":messagebox.showerror("Erro",event[2])
        except queue.Empty:pass
        self.after(100,self._poll)
    @staticmethod
    def _finding_metadata(path):
        try:
            info=os.stat(path,follow_symlinks=False)
            return {"size_bytes":info.st_size,"modified_time":info.st_mtime}
        except OSError:
            return {}
    def apply_manual(self):
        f=self._selected(self.result_tree)
        if not f:messagebox.showinfo("Classificação","Selecione um resultado.");return
        label=self.manual_choice.get();f.manual_classification=label
        audit_warning=self._audit_after_action("manual_classification",{"path":f.path,"label":label});self._rebuild();self.status.configure(text=f"Classificado manualmente como {label}.{audit_warning}")
    def mark_low(self):
        f=self._selected(self.danger_tree)
        if not f:messagebox.showinfo("Apps perigosos","Selecione um aplicativo.");return
        f.manual_classification="Baixo risco"
        audit_warning=self._audit_after_action("manual_classification",{"path":f.path,"label":"Baixo risco"});self._rebuild()
        if audit_warning:self.status.configure(text=audit_warning.strip())
    def _confirm_registry(self,path):
        matches,errors=matching_startup_values(path,False)
        if errors:messagebox.showwarning("Registro","Algumas chaves não puderam ser verificadas. "+"; ".join(errors))
        preview="\n\n".join(f"{item.label}\n  Dados: {item.value}" for item in matches)
        if matches and messagebox.askyesno("Referências de inicialização","Remover somente estes valores Run revisados?\n\n"+preview+"\n\nOs dados serão conferidos novamente. Nenhum outro valor será alterado."):
            removed,removal_errors=matching_startup_values(path,True,reviewed_values=matches)
            errors.extend(removal_errors)
            if removed:
                warning=self._audit_after_action("registry_values_removed",{"path":path,"values":[item.label for item in removed]})
                if warning:self.events.put(("audit_warning",warning.strip()))
        return errors
    def quarantine_selected(self):
        f=self._selected(self.danger_tree)
        if not f:messagebox.showinfo("Quarentena","Selecione um app perigoso ou suspeito.");return
        if not messagebox.askyesno("Confirmar quarentena",f"Mover para quarentena reversível?\n\n{f.path}\n\nO arquivo não será executado."):return
        try:
            meta=quarantine_file(f.path,f.sha256,f.file_identity,self.quarantine_dir)
            errors=self._confirm_registry(f.path);self.findings.remove(f);self._rebuild();audit_warning=self._audit_after_action("quarantine",meta)
            message="Arquivo em quarentena."+(" Falhas no Registro: "+"; ".join(errors) if errors else "")+audit_warning;messagebox.showinfo("Quarentena",message)
        except OSError as e:messagebox.showerror("Falha na quarentena",str(e))
    def delete_dangerous(self):
        f=self._selected(self.danger_tree)
        if not f:messagebox.showinfo("Exclusão","Selecione um app.");return
        if not messagebox.askyesno("Excluir permanentemente",f"Excluir este arquivo? A ação não pode ser desfeita.\n\n{f.path}"):return
        try:
            delete_file(f.path,f.sha256,f.file_identity);errors=self._confirm_registry(f.path);self.findings.remove(f);self._rebuild();audit_warning=self._audit_after_action("delete_file",{"path":f.path,"registry_errors":errors})
            message="Arquivo excluído."+(" Falhas no Registro: "+"; ".join(errors) if errors else "")+audit_warning;messagebox.showinfo("Exclusão",message)
        except OSError as e:messagebox.showerror("Falha ao excluir",str(e))
    def _delete_temp(self,f):
        delete_temp_file(f.path,f.sha256,f.file_identity);self.findings.remove(f)
        return self._audit_after_action("delete_temp_file",{"path":f.path,"sha256":f.sha256})
    def delete_temp_selected(self):
        f=self._selected(self.temp_tree)
        if not f:messagebox.showinfo("Temporários","Selecione um candidato.");return
        if not messagebox.askyesno("Excluir candidato","Pode estar em uso. Excluir somente este arquivo?\n\n"+f.path):return
        try:
            warning=self._delete_temp(f);self._rebuild();self.status.configure(text="Arquivo excluído."+warning)
        except OSError as e:messagebox.showerror("Não foi possível excluir",str(e))
    def delete_all_temps(self):
        candidates=[f for f in self.findings if is_temp_candidate(f.path)]
        if not candidates:messagebox.showinfo("Temporários","A lista não contém temporários.");return
        if not messagebox.askyesno("Confirmar exclusão",f"Excluir os {len(candidates)} itens listados? Cada arquivo será conferido; pastas e Registro não serão removidos."):return
        removed=0;errors=[];audit_warnings=[]
        for f in candidates:
            try:
                warning=self._delete_temp(f);removed+=1
                if warning:audit_warnings.append(f.path)
            except OSError as e:errors.append(f"{f.path}: {e}")
        self._rebuild();message=f"Excluídos: {removed}. Falhas na exclusão: {len(errors)}. Falhas no log de auditoria: {len(audit_warnings)}."
        if errors:message+="\n"+"\n".join(errors[:8])
        if audit_warnings:message+="\nArquivos excluídos sem registro: "+", ".join(audit_warnings[:8])
        messagebox.showinfo("Limpeza",message)
    def refresh_quarantine(self):
        if not hasattr(self,"quarantine_tree"):return
        selected=self.quarantine_tree.selection();y_pos=self.quarantine_tree.yview()[0]
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())
        try:
            for meta_path in self.quarantine_dir.glob("*.json"):
                try:
                    meta=json.loads(meta_path.read_text(encoding="utf-8"))
                    original=meta.get("original_path","");stored=meta.get("quarantine_path","")
                    display_path=getattr(self,"_display_path",None)
                    if display_path:
                        original=display_path(original);stored=display_path(stored)
                    self.quarantine_tree.insert("","end",iid=str(meta_path),values=(original,stored))
                except (OSError,json.JSONDecodeError):continue
        except OSError:pass
        available=set(self.quarantine_tree.get_children(""));valid=[iid for iid in selected if iid in available]
        if valid:self.quarantine_tree.selection_set(valid)
        self.quarantine_tree.yview_moveto(y_pos)
        if hasattr(self,"tree_sort_state") and self.quarantine_tree in self.tree_sort_state:
            self._apply_tree_sort(self.quarantine_tree)
        if valid:self.show_quarantine_detail()
        elif hasattr(self,"quarantine_detail"):self._set_detail(self.quarantine_detail,"Selecione um item para ver os detalhes.")
    def show_quarantine_detail(self):
        sel=self.quarantine_tree.selection()
        if not sel:
            if hasattr(self,"quarantine_detail"):self._set_detail(self.quarantine_detail,"Selecione um item para ver os detalhes.")
            return
        try:
            meta=json.loads(Path(sel[0]).read_text(encoding="utf-8"));self._set_detail(self.quarantine_detail,"\n".join(f"{k}: {v}" for k,v in meta.items()))
        except (OSError,json.JSONDecodeError) as e:self._set_detail(self.quarantine_detail,str(e))
    def restore_selected(self):
        sel=self.quarantine_tree.selection()
        if not sel:messagebox.showinfo("Quarentena","Selecione um item.");return
        try:
            meta_path=Path(sel[0]);entry=inspect_quarantine_entry(meta_path,self.quarantine_dir);meta=entry["meta"];dest=entry["destination"]
            if dest.exists():raise OSError("Caminho original ocupado; escolha outro local manualmente.")
            prompt=f"Restaurar ao caminho original?\n\n{dest}"
            if entry["legacy_hash_missing"]:prompt+="\n\nEste item antigo não tem hash registrado; não é possível confirmar sua integridade."
            if not messagebox.askyesno("Restaurar",prompt):return
            restored=restore_file(meta_path,self.quarantine_dir);self.refresh_quarantine();audit_warning=self._audit_after_action("restore_quarantine",restored);cleanup_warning=restored.get("cleanup_warning","");messagebox.showinfo("Quarentena","Restaurado. Analise novamente antes de executar."+("\n"+cleanup_warning if cleanup_warning else "")+audit_warning)
        except (OSError,KeyError,json.JSONDecodeError) as e:messagebox.showerror("Falha ao restaurar",str(e))
    def save_report(self):
        if not self.findings:messagebox.showinfo("Relatório","Ainda não há resultados.");return
        target=filedialog.asksaveasfilename(title="Salvar relatório",defaultextension=".json",filetypes=[("Relatório JSON","*.json")],initialfile="relatorio-seguranca.json")
        if not target:return
        payload=build_report(self.findings,self.scan_summary)
        try:
            write_report(target,payload);audit_warning=self._audit_after_action("report_exported",{"path":target,"findings":len(self.findings)});messagebox.showinfo("Relatório","Relatório JSON salvo."+audit_warning)
        except OSError as e:messagebox.showerror("Erro ao salvar relatório",str(e))
