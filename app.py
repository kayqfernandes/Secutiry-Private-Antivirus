"""Personal Security Analyzer. Scans read-only; remediation requires explicit confirmation."""
from __future__ import annotations
import ctypes, hashlib, json, os, queue, shutil, subprocess, threading, urllib.error, urllib.request, uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

APP_NAME = "Analisador de Segurança Pessoal"
EXECUTABLES = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}
TEMP_MARKERS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\")
RUN_KEYS = (("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"), ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"), ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"))

@dataclass
class Finding:
    path: str
    sha256: str = ""
    kind: str = "Arquivo"
    signature: str = "Não verificada"
    risk: str = "Inconclusivo"
    reasons: str = ""
    reputation: str = "Não consultada"
    manual_classification: str = ""

def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()

def is_executable(path: str) -> bool: return Path(path).suffix.lower() in EXECUTABLES

def temp_roots() -> list[str]:
    roots=[os.environ.get("TEMP"),os.environ.get("TMP"),os.path.join(os.environ.get("LOCALAPPDATA",""),"Temp"),os.path.join(os.environ.get("WINDIR",r"C:\Windows"),"Temp")]
    return list(dict.fromkeys(os.path.abspath(p) for p in roots if p and os.path.isdir(p)))

def is_temp_candidate(path: str) -> bool:
    p=os.path.normcase(os.path.abspath(path))
    for root in temp_roots():
        try:
            r=os.path.normcase(os.path.abspath(root))
            if os.path.commonpath((p,r))==r:return True
        except (ValueError,OSError):pass
    return any(marker in path.lower() for marker in TEMP_MARKERS)

def classify(path: str, signature: str="Não verificada", defender_hit: bool=False, hash_ok: bool=True) -> tuple[str,str,str]:
    executable=is_executable(path)
    if defender_hit:return "Alto risco","Uma detecção disponível do Microsoft Defender menciona este caminho; confira data e detalhes.","Executável" if executable else "Arquivo"
    if not hash_ok:return "Inconclusivo","Não foi possível calcular o hash; o arquivo pode estar inacessível ou ter mudado.","Executável" if executable else "Arquivo"
    reasons=[]
    if executable and is_temp_candidate(path):reasons.append("Executável em uma pasta temporária.")
    if signature=="Inválida":reasons.append("Assinatura digital inválida ou não confiável segundo o Windows.")
    elif executable and signature=="Não assinada":reasons.append("Executável sem assinatura digital verificada.")
    if reasons:return "Suspeito"," ".join(reasons)+" Isso requer análise; não confirma malware.","Executável" if executable else "Arquivo"
    if executable and signature=="Válida":return "Baixo risco","Assinatura válida segundo o Windows; isso não garante que o arquivo seja seguro.","Executável"
    return "Inconclusivo","Nenhuma detecção local conhecida; não é possível concluir que o arquivo é seguro.","Executável" if executable else "Arquivo"

def powershell(command: str, timeout: int=20) -> str:
    if os.name!="nt":raise OSError("Integração disponível somente no Windows.")
    return subprocess.check_output(["powershell.exe","-NoProfile","-NonInteractive","-Command",command],text=True,stderr=subprocess.STDOUT,timeout=timeout,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)).strip()

def signature_status(path: str) -> str:
    try:output=powershell(f"$s=Get-AuthenticodeSignature -LiteralPath '{path.replace(chr(39),chr(39)*2)}'; $s.Status.ToString()",timeout=12)
    except Exception:return "Não verificada"
    return {"Valid":"Válida","NotSigned":"Não assinada","HashMismatch":"Inválida","NotTrusted":"Inválida","UnknownError":"Inválida"}.get(output,"Não verificada")

def defender_scan(scan_type: str="FullScan",path: str|None=None) -> list[str]:
    if scan_type=="CustomScan":start=f"Start-MpScan -ScanType CustomScan -ScanPath '{(path or '').replace(chr(39),chr(39)*2)}' -ErrorAction Stop"
    else:start="Start-MpScan -ScanType FullScan -ErrorAction Stop"
    output=powershell(f"{start}; Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object {{$_.Resources}} | ConvertTo-Json -Compress",timeout=3600)
    try:parsed=json.loads(output) if output else []
    except json.JSONDecodeError:parsed=[]
    if isinstance(parsed,str):parsed=[parsed]
    return [str(x) for x in parsed or []]

def startup_entries() -> list[str]:
    if os.name!="nt":return []
    results=[]
    try:
        import winreg
        hives={"HKCU":winreg.HKEY_CURRENT_USER,"HKLM":winreg.HKEY_LOCAL_MACHINE}
        for hive_name,subkey in RUN_KEYS:
            try:
                with winreg.OpenKey(hives[hive_name],subkey) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name,value,_=winreg.EnumValue(key,i);results.append(f"Registro de inicialização: {name} → {value}")
            except OSError:pass
    except Exception:pass
    for folder in (Path(os.environ.get("APPDATA",""))/r"Microsoft\Windows\Start Menu\Programs\Startup",Path(os.environ.get("PROGRAMDATA",""))/r"Microsoft\Windows\Start Menu\Programs\Startup"):
        try:
            for item in folder.iterdir():results.append(f"Inicialização: {item}")
        except OSError:pass
    return results

def matching_startup_values(file_path: str,remove: bool=False) -> tuple[list[str],list[str]]:
    """Only inspect common Run values that contain this file's full path."""
    if os.name!="nt":return [],["Limpeza do Registro só está disponível no Windows."]
    import winreg
    hives={"HKCU":winreg.HKEY_CURRENT_USER,"HKLM":winreg.HKEY_LOCAL_MACHINE}; target=os.path.normcase(os.path.abspath(file_path)).casefold();matched=[];errors=[]
    for hive_name,subkey in RUN_KEYS:
        access=winreg.KEY_QUERY_VALUE|(winreg.KEY_SET_VALUE if remove else 0)
        try:
            with winreg.OpenKey(hives[hive_name],subkey,0,access) as key:
                names=[]
                for i in range(winreg.QueryInfoKey(key)[1]):
                    try:
                        name,value,_=winreg.EnumValue(key,i)
                        if isinstance(value,str) and target in os.path.normcase(value).casefold():names.append(name)
                    except OSError:continue
                for name in names:
                    matched.append(f"{hive_name}\\{subkey}\\{name}")
                    if remove:
                        try:winreg.DeleteValue(key,name)
                        except OSError as exc:errors.append(f"{hive_name}\\{subkey}\\{name}: {exc}")
        except FileNotFoundError:pass
        except OSError as exc:errors.append(f"{hive_name}\\{subkey}: {exc}")
    return matched,errors

def drives() -> list[str]:
    if os.name!="nt":return [str(Path.home())]
    mask=ctypes.windll.kernel32.GetLogicalDrives()
    return [f"{chr(65+i)}:\\" for i in range(26) if mask&(1<<i)]

def reputation_lookup(digest: str,api_key: str) -> str:
    req=urllib.request.Request("https://www.virustotal.com/api/v3/files/"+digest,headers={"x-apikey":api_key,"Accept":"application/json"})
    with urllib.request.urlopen(req,timeout=12) as response:data=json.loads(response.read().decode("utf-8"))
    stats=data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    return f"VirusTotal: {stats.get('malicious',0)} detecção(ões), {stats.get('suspicious',0)} suspeita(s) (terceiros)."

class Scanner:
    def __init__(self,audit_path: Path):self.audit_path=audit_path
    def audit(self,event: str,details: dict):
        self.audit_path.parent.mkdir(parents=True,exist_ok=True)
        with self.audit_path.open("a",encoding="utf-8") as f:f.write(json.dumps({"time":datetime.now(timezone.utc).isoformat(),"event":event,"details":details},ensure_ascii=False)+"\n")
    def scan(self,roots: list[str],callback,cancel: threading.Event,api_key="",defender_paths=()):
        count=0;findings=[];hits=[str(x).casefold() for x in defender_paths]
        for root in roots:
            for current,dirs,files in os.walk(root,onerror=lambda _e:None,followlinks=False):
                if cancel.is_set():return findings,count,True
                dirs[:]=[d for d in dirs if not os.path.islink(os.path.join(current,d))]
                for filename in files:
                    if cancel.is_set():return findings,count,True
                    path=os.path.join(current,filename);count+=1
                    try:
                        digest=sha256_file(path);sig=signature_status(path) if is_executable(path) else "N/A";normalized=os.path.normcase(os.path.abspath(path)).casefold();hit=any(normalized in item or item in normalized for item in hits);risk,why,kind=classify(path,sig,hit)
                        rep="Não consultada"
                        if api_key:
                            try:rep=reputation_lookup(digest,api_key)
                            except urllib.error.HTTPError as e:rep=f"Consulta falhou (HTTP {e.code})."
                            except Exception:rep="Consulta falhou; sem resultado disponível."
                        finding=Finding(path,digest,kind,sig,risk,why,rep)
                    except OSError as exc:
                        risk,why,kind=classify(path,hash_ok=False);finding=Finding(path,"",kind,"Não verificada",risk,f"{why} {exc}")
                    findings.append(finding);callback(finding,count)
        return findings,count,False

class App(tk.Tk):
    COLORS={"Perigoso":"#ff5c70","Alto risco":"#ff5c70","Suspeito":"#ffbd4a","Baixo risco":"#68d6a5","Inconclusivo":"#a9b5c7"}
    def __init__(self):
        super().__init__();self.title(APP_NAME);self.geometry("1180x760");self.minsize(900,620);self.configure(bg="#11151d")
        base=Path(os.environ.get("LOCALAPPDATA",str(Path.home())))/"PersonalSecurityAnalyzer";self.quarantine_dir=base/"Quarantine";self.events=queue.Queue();self.cancel_event=threading.Event();self.scanner=Scanner(base/"audit.jsonl");self.findings=[];self.by_iid={};self._style();self._layout();self.after(100,self._poll)
    def _style(self):
        s=ttk.Style(self);s.theme_use("clam");s.configure(".",background="#11151d",foreground="#e7ebf2",fieldbackground="#1a2130",bordercolor="#293346",font=("Segoe UI",10));s.configure("TFrame",background="#11151d");s.configure("TLabel",background="#11151d",foreground="#e7ebf2");s.configure("Title.TLabel",font=("Segoe UI",20,"bold"));s.configure("Muted.TLabel",foreground="#9aa7ba");s.configure("TButton",background="#263348",foreground="#f5f7fa",padding=8);s.map("TButton",background=[("active","#354866")]);s.configure("Treeview",background="#171e29",fieldbackground="#171e29",foreground="#e7ebf2",rowheight=28);s.configure("Treeview.Heading",background="#263348",foreground="#e7ebf2");s.map("Treeview",background=[("selected","#31527b")])
    def _layout(self):
        top=ttk.Frame(self,padding=18);top.pack(fill="x");ttk.Label(top,text=APP_NAME,style="Title.TLabel").pack(anchor="w");ttk.Label(top,text="Análise somente de leitura até você escolher uma ação • Nenhum item é executado",style="Muted.TLabel").pack(anchor="w",pady=(4,12))
        bar=ttk.Frame(top);bar.pack(fill="x");ttk.Button(bar,text="Analisar pasta…",command=self.choose_folder).pack(side="left",padx=(0,7));ttk.Button(bar,text="Analisar computador",command=self.full_scan).pack(side="left",padx=7);ttk.Button(bar,text="Defender na pasta…",command=self.defender_folder).pack(side="left",padx=7);ttk.Button(bar,text="Cancelar busca",command=self.cancel_scan).pack(side="left",padx=7);ttk.Button(bar,text="Salvar relatório…",command=self.save_report).pack(side="left",padx=7);self.online=tk.BooleanVar(value=False);ttk.Checkbutton(bar,text="Reputação online (só hashes)",variable=self.online).pack(side="left",padx=12)
        stat=ttk.Frame(self,padding=(18,0,18,10));stat.pack(fill="x");self.status=ttk.Label(stat,text="Pronto.",style="Muted.TLabel");self.status.pack(side="left");self.progress=ttk.Progressbar(stat,mode="indeterminate",length=180);self.progress.pack(side="right")
        self.tabs=ttk.Notebook(self);self.tabs.pack(fill="both",expand=True,padx=18,pady=(0,12))
        self.results_tab=ttk.Frame(self.tabs,padding=10);self.danger_tab=ttk.Frame(self.tabs,padding=10);self.temp_tab=ttk.Frame(self.tabs,padding=10);self.quarantine_tab=ttk.Frame(self.tabs,padding=10)
        self.tabs.add(self.results_tab,text="Resultados");self.tabs.add(self.danger_tab,text="Apps perigosos / suspeitos");self.tabs.add(self.temp_tab,text="Candidatos temporários");self.tabs.add(self.quarantine_tab,text="Quarentena")
        self.result_tree=self._make_tree(self.results_tab);self.result_tree.bind("<<TreeviewSelect>>",lambda _e:self.show_detail(self.result_tree))
        row=ttk.Frame(self.results_tab);row.pack(fill="x",pady=8);ttk.Label(row,text="Classificação manual:").pack(side="left");self.manual_choice=tk.StringVar(value="Perigoso");ttk.Combobox(row,textvariable=self.manual_choice,values=("Perigoso","Baixo risco"),state="readonly",width=18).pack(side="left",padx=7);ttk.Button(row,text="Aplicar ao selecionado",command=self.apply_manual).pack(side="left");self.result_detail=self._detail(self.results_tab)
        self.danger_tree=self._make_tree(self.danger_tab);self.danger_tree.bind("<<TreeviewSelect>>",lambda _e:self.show_detail(self.danger_tree))
        row=ttk.Frame(self.danger_tab);row.pack(fill="x",pady=8);ttk.Button(row,text="Deixar / marcar baixo risco",command=self.mark_low).pack(side="left",padx=4);ttk.Button(row,text="Colocar em quarentena",command=self.quarantine_selected).pack(side="left",padx=4);ttk.Button(row,text="Excluir arquivo…",command=self.delete_dangerous).pack(side="left",padx=4);self.danger_detail=self._detail(self.danger_tab)
        self.temp_tree=self._make_tree(self.temp_tab);self.temp_tree.bind("<<TreeviewSelect>>",lambda _e:self.show_detail(self.temp_tree))
        row=ttk.Frame(self.temp_tab);row.pack(fill="x",pady=8);ttk.Button(row,text="Buscar temporários",command=self.scan_temps).pack(side="left",padx=4);ttk.Button(row,text="Excluir selecionado…",command=self.delete_temp_selected).pack(side="left",padx=4);ttk.Button(row,text="Excluir todos listados…",command=self.delete_all_temps).pack(side="left",padx=4);self.temp_detail=self._detail(self.temp_tab)
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
    def _risk_text(self,f):return f.manual_classification or f.risk
    def _row(self,tree,f):
        label=self._risk_text(f);tree.insert("","end",iid=str(id(f)),values=(label,f.kind,f.signature,f.path),tags=(label if label in self.COLORS else "Inconclusivo",))
    def _selected(self,tree):
        sel=tree.selection();return self.by_iid.get(sel[0]) if sel else None
    def _rebuild(self):
        self.by_iid={str(id(f)):f for f in self.findings}
        for tree in (self.result_tree,self.danger_tree,self.temp_tree):tree.delete(*tree.get_children())
        for f in self.findings:
            self._row(self.result_tree,f)
            if (f.manual_classification=="Perigoso" or (not f.manual_classification and f.risk in ("Alto risco","Suspeito"))) and is_executable(f.path):self._row(self.danger_tree,f)
            if is_temp_candidate(f.path):self._row(self.temp_tree,f)
        self.refresh_quarantine()
    def show_detail(self,tree):
        f=self._selected(tree)
        if not f:return
        text=f"Classificação: {self._risk_text(f)}\nMotivos: {f.reasons}\nSHA-256: {f.sha256 or 'indisponível'}\nAssinatura: {f.signature}\nReputação: {f.reputation}"
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
        try:
            paths=defender_scan("CustomScan",folder);self.scanner.audit("defender_custom_scan",{"path":folder,"reported_resources":len(paths)});self.events.put(("defender_results",folder,paths))
        except Exception as e:self.events.put(("message",f"Defender indisponível ou falhou: {e}"))
    def scan_temps(self):
        roots=temp_roots()
        if not roots:messagebox.showinfo("Temporários","Não encontrei pastas temporárias acessíveis.");return
        self.tabs.select(self.temp_tab);self.start_scan(roots)
    def start_scan(self,roots,ask_defender=False):
        self.cancel_event.clear();self.progress.start(12);self.status.configure(text="Buscando e analisando arquivos…");self.findings=[];self._rebuild();key=""
        if self.online.get():
            key=simpledialog.askstring("Consulta por hash","Cole sua chave VirusTotal. Apenas hashes serão enviados; a chave não é guardada.",show="*",parent=self)
            if not key:self.online.set(False)
        threading.Thread(target=self._worker,args=(roots,key,ask_defender),daemon=True).start()
    def cancel_scan(self):self.cancel_event.set();self.status.configure(text="Parando após o arquivo atual…")
    def _worker(self,roots,key,ask_defender=False):
        defender=[]
        if ask_defender:
            try:
                defender=defender_scan("FullScan")
                self.events.put(("message",f"Defender: verificação solicitada; {len(defender)} recurso(s) reportado(s)."))
            except Exception as e:
                self.events.put(("message",f"Defender indisponível ou falhou; análise local continua: {e}"))
        starts=startup_entries();self.scanner.audit("scan_started",{"roots":roots,"online_hash_lookup":bool(key),"startup_items_found":len(starts)})
        for entry in starts:self.events.put(("startup",entry))
        found,count,cancelled=self.scanner.scan(roots,lambda f,n:self.events.put(("finding",f,n)),self.cancel_event,key,defender)
        self.scanner.audit("scan_finished",{"files":count,"findings":len(found),"cancelled":cancelled});self.events.put(("done",count,cancelled))
    def _poll(self):
        try:
            while True:
                event=self.events.get_nowait();typ=event[0]
                if typ=="finding":
                    f,n=event[1:];self.findings.append(f);self.by_iid[str(id(f))]=f;self._row(self.result_tree,f)
                    if is_temp_candidate(f.path):self._row(self.temp_tree,f)
                    if f.risk in ("Alto risco","Suspeito") and is_executable(f.path):self._row(self.danger_tree,f)
                    self.status.configure(text=f"Analisados: {n} • Suspeitos: {sum(x.risk=='Suspeito' for x in self.findings)} • Alto risco: {sum(x.risk=='Alto risco' for x in self.findings)}")
                elif typ=="startup":
                    f=Finding(event[1],kind="Inicialização",risk="Inconclusivo",reasons="Item comum de inicialização detectado; a presença sozinha não indica ameaça.");self.findings.append(f);self.by_iid[str(id(f))]=f;self._row(self.result_tree,f)
                elif typ=="done":
                    self.progress.stop();self._rebuild();self.status.configure(text=f"Concluído: {event[1]} arquivo(s) analisado(s)"+(" (cancelado)" if event[2] else ""))
                elif typ=="defender_results":
                    folder,paths=event[1],event[2];added=0
                    for resource in paths:
                        path=str(resource)
                        if path.lower().startswith("file:_"):path=path[6:]
                        f=Finding(path,kind="Executável" if is_executable(path) else "Arquivo",risk="Alto risco",reasons="Recurso reportado pelas detecções disponíveis do Microsoft Defender.")
                        self.findings.append(f);added+=1
                    self._rebuild();self.status.configure(text=f"Defender: {added} recurso(s) reportado(s) para {folder}.")
                elif typ=="message":self.status.configure(text=event[1])
                elif typ=="error":messagebox.showerror("Erro",event[1])
        except queue.Empty:pass
        self.after(100,self._poll)
    def apply_manual(self):
        f=self._selected(self.result_tree)
        if not f:messagebox.showinfo("Classificação","Selecione um resultado.");return
        label=self.manual_choice.get();f.manual_classification=label;f.reasons=(f.reasons+" | " if f.reasons else "")+f"Classificação manual escolhida pelo usuário: {label}; não é conclusão automática."
        self.scanner.audit("manual_classification",{"path":f.path,"label":label});self._rebuild();self.status.configure(text=f"Classificado manualmente como {label}.")
    def mark_low(self):
        f=self._selected(self.danger_tree)
        if not f:messagebox.showinfo("Apps perigosos","Selecione um aplicativo.");return
        f.manual_classification="Baixo risco";f.reasons=(f.reasons+" | " if f.reasons else "")+"Usuário escolheu deixar o arquivo; isso não certifica segurança."
        self.scanner.audit("manual_classification",{"path":f.path,"label":"Baixo risco"});self._rebuild()
    def _confirm_registry(self,path):
        matches,errors=matching_startup_values(path,False)
        if errors:messagebox.showwarning("Registro","Algumas chaves não puderam ser verificadas. "+"; ".join(errors))
        if matches and messagebox.askyesno("Referências de inicialização","Remover somente estes valores Run que mencionam o caminho completo?\n\n"+"\n".join(matches)+"\n\nNenhum outro Registro será alterado."):
            _,errors=matching_startup_values(path,True)
        return errors
    def quarantine_selected(self):
        f=self._selected(self.danger_tree)
        if not f:messagebox.showinfo("Quarentena","Selecione um app perigoso ou suspeito.");return
        if not messagebox.askyesno("Confirmar quarentena",f"Mover para quarentena reversível?\n\n{f.path}\n\nO arquivo não será executado."):return
        try:
            source=Path(f.path)
            if not source.is_file() or source.is_symlink():raise OSError("O caminho não é arquivo regular.")
            if f.sha256 and sha256_file(f.path)!=f.sha256:raise OSError("Arquivo mudou desde a análise; faça nova busca.")
            self.quarantine_dir.mkdir(parents=True,exist_ok=True);stored=self.quarantine_dir/(uuid.uuid4().hex+".quarantined");meta_path=self.quarantine_dir/(stored.stem+".json")
            meta={"original_path":f.path,"quarantine_path":str(stored),"sha256":f.sha256,"quarantined_at":datetime.now(timezone.utc).isoformat()}
            try:
                shutil.move(f.path,str(stored));meta_path.write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding="utf-8")
            except OSError:
                if stored.exists() and not Path(f.path).exists():shutil.move(str(stored),f.path)
                if meta_path.exists():meta_path.unlink()
                raise
            errors=self._confirm_registry(f.path);self.findings.remove(f);self.scanner.audit("quarantine",meta);self._rebuild()
            message="Arquivo em quarentena."+(" Falhas no Registro: "+"; ".join(errors) if errors else "");messagebox.showinfo("Quarentena",message)
        except OSError as e:messagebox.showerror("Falha na quarentena",str(e))
    def delete_dangerous(self):
        f=self._selected(self.danger_tree)
        if not f:messagebox.showinfo("Exclusão","Selecione um app.");return
        if not messagebox.askyesno("Excluir permanentemente",f"Excluir este arquivo? A ação não pode ser desfeita.\n\n{f.path}"):return
        try:
            path=Path(f.path)
            if not path.is_file() or path.is_symlink():raise OSError("O caminho não é arquivo regular.")
            if f.sha256 and sha256_file(f.path)!=f.sha256:raise OSError("Arquivo mudou desde a análise; faça nova busca.")
            path.unlink();errors=self._confirm_registry(f.path);self.findings.remove(f);self.scanner.audit("delete_file",{"path":f.path,"registry_errors":errors});self._rebuild()
            message="Arquivo excluído."+(" Falhas no Registro: "+"; ".join(errors) if errors else "");messagebox.showinfo("Exclusão",message)
        except OSError as e:messagebox.showerror("Falha ao excluir",str(e))
    def _delete_temp(self,f):
        if not is_temp_candidate(f.path):raise OSError("Caminho não está em uma pasta temporária reconhecida.")
        path=Path(f.path)
        if not path.is_file() or path.is_symlink():raise OSError("Somente arquivos regulares podem ser excluídos aqui.")
        if f.sha256 and sha256_file(f.path)!=f.sha256:raise OSError("Arquivo mudou; refaça a busca antes de agir.")
        path.unlink();self.scanner.audit("delete_temp_file",{"path":f.path,"sha256":f.sha256});self.findings.remove(f)
    def delete_temp_selected(self):
        f=self._selected(self.temp_tree)
        if not f:messagebox.showinfo("Temporários","Selecione um candidato.");return
        if not messagebox.askyesno("Excluir candidato","Pode estar em uso. Excluir somente este arquivo?\n\n"+f.path):return
        try:self._delete_temp(f);self._rebuild();self.status.configure(text="Arquivo excluído.")
        except OSError as e:messagebox.showerror("Não foi possível excluir",str(e))
    def delete_all_temps(self):
        candidates=[f for f in self.findings if is_temp_candidate(f.path)]
        if not candidates:messagebox.showinfo("Temporários","A lista não contém temporários.");return
        if not messagebox.askyesno("Confirmar exclusão",f"Excluir os {len(candidates)} itens listados? Cada arquivo será conferido; pastas e Registro não serão removidos."):return
        removed=0;errors=[]
        for f in candidates:
            try:self._delete_temp(f);removed+=1
            except OSError as e:errors.append(f"{f.path}: {e}")
        self._rebuild();messagebox.showinfo("Limpeza",f"Excluídos: {removed}. Falhas: {len(errors)}."+("\n"+"\n".join(errors[:8]) if errors else ""))
    def refresh_quarantine(self):
        if not hasattr(self,"quarantine_tree"):return
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())
        try:
            for meta_path in self.quarantine_dir.glob("*.json"):
                try:
                    meta=json.loads(meta_path.read_text(encoding="utf-8"));self.quarantine_tree.insert("","end",iid=str(meta_path),values=(meta.get("original_path",""),meta.get("quarantine_path","")))
                except (OSError,json.JSONDecodeError):continue
        except OSError:pass
    def show_quarantine_detail(self):
        sel=self.quarantine_tree.selection()
        if not sel:return
        try:
            meta=json.loads(Path(sel[0]).read_text(encoding="utf-8"));self._set_detail(self.quarantine_detail,"\n".join(f"{k}: {v}" for k,v in meta.items()))
        except (OSError,json.JSONDecodeError) as e:self._set_detail(self.quarantine_detail,str(e))
    def restore_selected(self):
        sel=self.quarantine_tree.selection()
        if not sel:messagebox.showinfo("Quarentena","Selecione um item.");return
        try:
            meta_path=Path(sel[0]);meta=json.loads(meta_path.read_text(encoding="utf-8"));src=Path(meta["quarantine_path"]);dest=Path(meta["original_path"])
            if not src.is_file():raise OSError("Arquivo em quarentena não encontrado.")
            if dest.exists():raise OSError("Caminho original ocupado; escolha outro local manualmente.")
            if not messagebox.askyesno("Restaurar",f"Restaurar ao caminho original?\n\n{dest}"):return
            dest.parent.mkdir(parents=True,exist_ok=True);shutil.move(str(src),str(dest));meta_path.unlink();self.scanner.audit("restore_quarantine",meta);self.refresh_quarantine();messagebox.showinfo("Quarentena","Restaurado. Analise novamente antes de executar.")
        except (OSError,KeyError,json.JSONDecodeError) as e:messagebox.showerror("Falha ao restaurar",str(e))
    def save_report(self):
        if not self.findings:messagebox.showinfo("Relatório","Ainda não há resultados.");return
        target=filedialog.asksaveasfilename(title="Salvar relatório",defaultextension=".json",filetypes=[("Relatório JSON","*.json")],initialfile="relatorio-seguranca.json")
        if not target:return
        labels=("Perigoso","Alto risco","Suspeito","Baixo risco","Inconclusivo");summary={r:sum(self._risk_text(f)==r for f in self.findings) for r in labels}
        payload={"generated_at":datetime.now(timezone.utc).isoformat(),"summary":summary,"findings":[asdict(f) for f in self.findings]}
        try:
            Path(target).write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8");self.scanner.audit("report_exported",{"path":target,"findings":len(self.findings)});messagebox.showinfo("Relatório","Relatório JSON salvo.")
        except OSError as e:messagebox.showerror("Erro ao salvar relatório",str(e))

if __name__ == "__main__":App().mainloop()





