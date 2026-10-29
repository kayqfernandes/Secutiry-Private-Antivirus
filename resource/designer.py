"""Interface design system and visual window for the security analyzer."""
import math
import os
import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

from src.security_analyzer.app.window import App as _BaseApp
from src.security_analyzer.core.models import is_executable, is_temp_candidate
from src.security_analyzer.core.static_inspection import inspect_source_file
from src.security_analyzer.integrations.drives import enumerate_volumes
from src.security_analyzer.integrations.installed_apps import enumerate_installed_applications


BG = "#10002B"
PANEL = "#240046"
BORDER = "#3C096C"
ACTIVE_TAB = "#5A189A"
PRIMARY = "#7B2CBF"
HOVER = "#9D4EDD"
SECONDARY = "#C77DFF"
TEXT = "#E0AAFF"
WHITE = "#FFFFFF"
REBUILD_BATCH_SIZE = 250


def _rounded_points(x1, y1, x2, y2, radius):
    points = []
    corners = ((x2-radius, y1+radius, -90), (x2-radius, y2-radius, 0),
               (x1+radius, y2-radius, 90), (x1+radius, y1+radius, 180))
    for cx, cy, start in corners:
        for step in range(7):
            angle = math.radians(start + step * 90 / 6)
            points.extend((cx + math.cos(angle)*radius, cy + math.sin(angle)*radius))
    return points


class RoundedPanel(tk.Frame):
    """Canvas-backed rounded container for ordinary Tk/ttk widgets."""
    def __init__(self, parent, *, color=PANEL, border=BORDER, radius=18, padding=12,
                 fixed_height=None, **kwargs):
        super().__init__(parent, bg=parent.cget("bg"), **kwargs)
        self.color, self.border, self.radius, self.padding = color, border, radius, padding
        if fixed_height is not None:
            self.configure(height=fixed_height)
            self.pack_propagate(False)
        self.canvas = tk.Canvas(self, bg=parent.cget("bg"), highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)
        if fixed_height is not None:
            self.canvas.configure(height=fixed_height)
        self.content = tk.Frame(self.canvas, bg=color)
        self.window = self.canvas.create_window(padding, padding, anchor="nw", window=self.content)
        self.shape = None
        self.canvas.bind("<Configure>", self._resize)

    def _resize(self, event):
        width, height = max(event.width, 1), max(event.height, 1)
        inset = self.padding
        self.canvas.coords(self.window, inset, inset)
        self.canvas.itemconfigure(self.window, width=max(1, width-2*inset), height=max(1, height-2*inset))
        if self.shape is not None:
            self.canvas.delete(self.shape)
        self.shape = self.canvas.create_polygon(
            *_rounded_points(1, 1, width-1, height-1, min(self.radius, width/2, height/2)),
            smooth=True, splinesteps=24, fill=self.color, outline=self.border, width=1,
        )
        self.canvas.tag_lower(self.shape)


class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command, *, primary=False, state="normal", width=None):
        self.label, self.command, self.primary = text, command, primary
        self.state = state
        self.normal_color = PRIMARY if primary else BG
        self.hover_color = HOVER if primary else PANEL
        self.foreground = WHITE if primary else TEXT
        super().__init__(parent, height=38, width=width or max(94, len(text)*8+28),
                         bg=parent.cget("bg"), highlightthickness=0, bd=0, cursor="hand2")
        self.shape = self.create_polygon(0, 0, 0, 0, smooth=True, splinesteps=20,
                                         fill=self.normal_color, outline=BORDER if not primary else PRIMARY, width=1)
        self.caption = self.create_text(0, 0, text=text, fill=self.foreground,
                                        font=("Segoe UI", 9, "bold" if primary else "normal"))
        self.bind("<Configure>", self._resize)
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.bind("<Button-1>", self._click)
        self.bind("<Return>", self._click)
        self.bind("<space>", self._click)
        self._paint()

    def _resize(self, event):
        self.coords(self.shape, *_rounded_points(1, 1, event.width-1, event.height-1, 12))
        self.coords(self.caption, event.width/2, event.height/2)

    def _paint(self, color=None):
        disabled = self.state == "disabled"
        self.itemconfigure(self.shape, fill=color or ("#3C096C" if disabled else self.normal_color))
        self.itemconfigure(self.caption, fill="#A88BBF" if disabled else self.foreground)
        self.configure(cursor="arrow" if disabled else "hand2")

    def _enter(self, _event):
        if self.state != "disabled": self._paint(self.hover_color)

    def _leave(self, _event): self._paint()

    def _click(self, _event=None):
        if self.state != "disabled" and self.command: self.command()

    def configure(self, cnf=None, **kwargs):
        if "state" in kwargs:
            self.state = kwargs.pop("state")
            self._paint()
        if kwargs or cnf:
            return super().configure(cnf, **kwargs)

    config = configure


class RoundCheck(tk.Canvas):
    def __init__(self, parent, text, variable):
        self.variable, self.label = variable, text
        super().__init__(parent, height=34, width=204, bg=parent.cget("bg"), highlightthickness=0, bd=0, cursor="hand2")
        self.box = self.create_polygon(0, 0, 0, 0, smooth=True, fill=PANEL, outline=BORDER, width=1)
        self.mark = self.create_text(0, 0, text="", fill=WHITE, font=("Segoe UI", 10, "bold"))
        self.caption = self.create_text(29, 17, anchor="w", text=text, fill=SECONDARY, font=("Segoe UI", 9))
        self.bind("<Configure>", lambda e: self.coords(self.box, *_rounded_points(3, 7, 22, 26, 6)))
        self.bind("<Button-1>", self._toggle)
        self._trace = variable.trace_add("write", lambda *_: self._draw())
        self._draw()

    def _toggle(self, _event=None): self.variable.set(not self.variable.get())

    def _draw(self):
        checked = bool(self.variable.get())
        self.itemconfigure(self.box, fill=HOVER if checked else PANEL, outline=HOVER if checked else BORDER)
        self.itemconfigure(self.mark, text="✓" if checked else "")
        self.coords(self.mark, 12, 16)


class RoundedProgress(tk.Canvas):
    def __init__(self, parent, width=190):
        super().__init__(parent, height=12, width=width, bg=parent.cget("bg"), highlightthickness=0, bd=0)
        self.running = False
        self.offset = 0
        self.job = None
        self.bind("<Configure>", lambda _e: self._draw())
        self._draw()

    def _draw(self):
        self.delete("bar")
        width, height = max(1, self.winfo_width()), 8
        y = max(1, (self.winfo_height()-height)/2)
        self.create_polygon(*_rounded_points(1, y, width-1, y+height, height/2),
                            smooth=True, fill=PANEL, outline="", tags="bar")
        if self.running:
            segment = max(32, width*.28)
            x = (self.offset % (width+segment))-segment
            left, right = max(1, x), min(width-1, x+segment)
            if right > left:
                self.create_polygon(*_rounded_points(left, y, right, y+height, height/2),
                                    smooth=True, fill=HOVER, outline="", tags="bar")

    def start(self, _interval=12):
        self.running = True
        self._pulse()

    def _pulse(self):
        if not self.running: return
        self.offset += 9
        self._draw()
        self.job = self.after(30, self._pulse)

    def stop(self):
        self.running = False
        if self.job:
            try: self.after_cancel(self.job)
            except tk.TclError: pass
            self.job = None
        self._draw()


class PillTabs(tk.Frame):
    """Small notebook-compatible tab selector; select(page) remains supported."""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        selector = RoundedPanel(self, color=PANEL, border=PANEL, radius=19, padding=5,
                                fixed_height=54)
        selector.pack(fill="x", pady=(0, 14))
        self.selector = selector
        self.page_host = tk.Frame(self, bg=BG)
        self.page_host.pack(fill="both", expand=True)
        self.pages, self.buttons, self.current = [], {}, None

    def add(self, page, text):
        button_width = max(118, min(196, len(text)*7+28))
        button = RoundedButton(self.selector.content, text, lambda: self.select(page), width=button_width)
        button.pack(side="left", padx=3, pady=2)
        self.pages.append((page, text))
        self.buttons[page] = button
        if self.current is None: self.select(page)

    def select(self, page):
        for candidate, _label in self.pages:
            candidate.pack_forget()
        if page in self.buttons:
            self.current = page
            page.pack(fill="both", expand=True)
            for candidate, button in self.buttons.items():
                button.normal_color = ACTIVE_TAB if candidate is page else PANEL
                button.hover_color = HOVER if candidate is page else ACTIVE_TAB
                button.foreground = WHITE if candidate is page else SECONDARY
                button._paint()


class App(_BaseApp):
    """Existing application behavior with a replacement visual layer only."""
    COLORS = {
        "Perigoso": "#FF8FA3", "Alto risco": "#FF8FA3", "Suspeito": "#FFC97A",
        "Baixo risco": "#8FE3B8", "Inconclusivo": SECONDARY,
    }

    def _style(self):
        self.configure(bg=BG)
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Title.TLabel", background=BG, foreground=WHITE, font=("Segoe UI", 24, "bold"))
        style.configure("Muted.TLabel", background=BG, foreground=SECONDARY, font=("Segoe UI", 10))
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=44, borderwidth=0, relief="flat", bordercolor=PANEL,
                        lightcolor=PANEL, darkcolor=PANEL, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=PANEL, foreground=SECONDARY,
                        borderwidth=0, relief="flat", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", BORDER)],
                  foreground=[("selected", WHITE)], bordercolor=[("focus", PANEL)])
        style.configure("TCombobox", fieldbackground=PANEL, background=PANEL, foreground=TEXT,
                        arrowcolor=SECONDARY, bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL)], foreground=[("readonly", TEXT)])

    def _layout(self):
        shell = ttk.Frame(self, padding=(34, 25, 34, 22))
        shell.pack(fill="both", expand=True)
        heading = ttk.Frame(shell)
        heading.pack(fill="x", pady=(0, 17))
        ttk.Label(heading, text="Analisador de Segurança Pessoal", style="Title.TLabel").pack(anchor="w")
        ttk.Label(heading, text="Análise somente de leitura até você escolher uma ação • Nenhum item é executado",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 0))

        toolbar = tk.Frame(shell, bg=BG)
        toolbar.pack(fill="x", pady=(0, 16))
        self.folder_button = RoundedButton(toolbar, "Analisar pasta…", self.choose_folder, primary=True, width=124)
        self.folder_button.pack(side="left", padx=(0, 7))
        self.full_scan_button = RoundedButton(toolbar, "Analisar computador", self.full_scan, width=148)
        self.full_scan_button.pack(side="left", padx=4)
        self.defender_button = RoundedButton(toolbar, "Defender na pasta…", self.defender_folder, width=137)
        self.defender_button.pack(side="left", padx=4)
        self.cancel_button = RoundedButton(toolbar, "Cancelar busca", self.cancel_scan, state="disabled", width=117)
        self.cancel_button.pack(side="left", padx=4)
        RoundedButton(toolbar, "Salvar relatório…", self.save_report, width=129).pack(side="left", padx=4)
        self.online = tk.BooleanVar(value=False)
        RoundCheck(toolbar, "Reputação online (só hashes)", self.online).pack(side="left", padx=(8, 0))
        self.scan_trigger_buttons = [self.folder_button, self.full_scan_button, self.defender_button]

        status_row = tk.Frame(shell, bg=BG)
        status_row.pack(fill="x", pady=(0, 14))
        self.status = ttk.Label(status_row, text="Pronto.", style="Muted.TLabel")
        self.status.pack(side="left")
        self.progress = RoundedProgress(status_row, width=190)
        self.progress.pack(side="right")

        self.tabs = PillTabs(shell)
        self.tabs.pack(fill="both", expand=True)
        self.results_tab = tk.Frame(self.tabs.page_host, bg=BG)
        self.danger_tab = tk.Frame(self.tabs.page_host, bg=BG)
        self.temp_tab = tk.Frame(self.tabs.page_host, bg=BG)
        self.quarantine_tab = tk.Frame(self.tabs.page_host, bg=BG)
        self.storage_tab = tk.Frame(self.tabs.page_host, bg=BG)
        self.tabs.add(self.results_tab, "Resultados")
        self.tabs.add(self.danger_tab, "Apps perigosos / suspeitos")
        self.tabs.add(self.temp_tab, "Candidatos temporários")
        self.tabs.add(self.quarantine_tab, "Quarentena")
        self.tabs.add(self.storage_tab, "Armazenamento")

        self.tree_sort_state = {}
        self.tree_heading_titles = {}
        self._rebuild_generation = 0
        self._batch_rebuilding = False
        self._build_result_filters(self.results_tab)
        self.result_tree = self._make_tree(self.results_tab)
        self.result_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_detail(self.result_tree))
        row = tk.Frame(self.results_tab, bg=BG)
        row.pack(fill="x", pady=10)
        ttk.Label(row, text="Classificação manual:").pack(side="left", padx=(3, 8))
        self.manual_choice = tk.StringVar(value="Perigoso")
        ttk.Combobox(row, textvariable=self.manual_choice, values=("Perigoso", "Baixo risco"),
                     state="readonly", width=18).pack(side="left", padx=(0, 9))
        RoundedButton(row, "Aplicar ao selecionado", self.apply_manual, primary=True, width=176).pack(side="left")
        RoundedButton(row, "Inspecionar código…", lambda: self.inspect_selected_source(self.result_tree),
                      width=158).pack(side="left", padx=(8, 0))
        self.result_detail = self._detail(self.results_tab)

        self.danger_tree = self._make_tree(self.danger_tab)
        self.danger_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_detail(self.danger_tree))
        row = tk.Frame(self.danger_tab, bg=BG)
        row.pack(fill="x", pady=10)
        RoundedButton(row, "Deixar / marcar baixo risco", self.mark_low, width=207).pack(side="left", padx=3)
        RoundedButton(row, "Colocar em quarentena", self.quarantine_selected, width=168).pack(side="left", padx=3)
        RoundedButton(row, "Excluir arquivo…", self.delete_dangerous, width=138).pack(side="left", padx=3)
        RoundedButton(row, "Abrir diretório do arquivo", self.open_dangerous_location, width=194).pack(side="left", padx=3)
        RoundedButton(row, "Inspecionar código…", lambda: self.inspect_selected_source(self.danger_tree),
                      width=158).pack(side="left", padx=3)
        self.danger_detail = self._detail(self.danger_tab)

        self.temp_tree = self._make_tree(self.temp_tab)
        self.temp_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_detail(self.temp_tree))
        row = tk.Frame(self.temp_tab, bg=BG)
        row.pack(fill="x", pady=10)
        self.temp_scan_button = RoundedButton(row, "Buscar temporários", self.scan_temps, primary=True, width=150)
        self.temp_scan_button.pack(side="left", padx=3)
        self.scan_trigger_buttons.append(self.temp_scan_button)
        RoundedButton(row, "Excluir selecionado…", self.delete_temp_selected, width=158).pack(side="left", padx=3)
        RoundedButton(row, "Excluir todos listados…", self.delete_all_temps, width=176).pack(side="left", padx=3)
        self.temp_detail = self._detail(self.temp_tab)

        quarantine_panel = RoundedPanel(self.quarantine_tab, padding=10)
        quarantine_panel.pack(fill="both", expand=True)
        self.quarantine_tree = ttk.Treeview(quarantine_panel.content, columns=("original", "stored"),
                                            show="headings", height=12)
        self.quarantine_tree.heading("original", text="ARQUIVO ORIGINAL")
        self.quarantine_tree.heading("stored", text="ARQUIVO EM QUARENTENA")
        self.quarantine_tree.column("original", width=420, minwidth=250, anchor="w", stretch=True)
        self.quarantine_tree.column("stored", width=360, minwidth=230, anchor="w", stretch=True)
        quarantine_panel.content.grid_rowconfigure(0, weight=1)
        quarantine_panel.content.grid_columnconfigure(0, weight=1)
        self.quarantine_tree.grid(row=0, column=0, sticky="nsew")
        quarantine_y = ttk.Scrollbar(quarantine_panel.content, orient="vertical", command=self.quarantine_tree.yview)
        quarantine_y.grid(row=0, column=1, sticky="ns")
        self.quarantine_tree.configure(yscrollcommand=quarantine_y.set)
        self._enable_tree_sort(self.quarantine_tree, ("original", "stored"))
        self.quarantine_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_quarantine_detail())
        location = tk.Frame(self.quarantine_tab, bg=BG)
        location.pack(fill="x", pady=(8, 2))
        ttk.Label(location, text=f"Local dos arquivos: {self.quarantine_dir}", style="Muted.TLabel",
                  wraplength=760, justify="left").pack(anchor="w", padx=3)
        row = tk.Frame(self.quarantine_tab, bg=BG)
        row.pack(fill="x", pady=(5, 5))
        RoundedButton(row, "Abrir pasta", self.open_quarantine_location, width=116).pack(side="left", padx=3)
        RoundedButton(row, "Atualizar", self.refresh_quarantine, width=105).pack(side="left", padx=3)
        RoundedButton(row, "Restaurar selecionado…", self.restore_selected, width=181).pack(side="left", padx=3)
        self.quarantine_detail = self._detail(self.quarantine_tab)
        self.refresh_quarantine()

        storage_header = tk.Frame(self.storage_tab, bg=BG)
        storage_header.pack(fill="x", pady=(0, 10))
        ttk.Label(storage_header, text="Volumes montados", style="Title.TLabel").pack(side="left", padx=3)
        self.storage_refresh_button = RoundedButton(
            storage_header, "Atualizar discos", self.refresh_storage_volumes, width=142
        )
        self.storage_refresh_button.pack(side="right", padx=3)
        ttk.Label(self.storage_tab,
                  text="Esta lista mostra os discos e a capacidade disponível. Abrir a aba não inicia uma varredura.",
                  style="Muted.TLabel", wraplength=900, justify="left").pack(anchor="w", padx=3, pady=(0, 10))
        storage_actions = tk.Frame(self.storage_tab, bg=BG)
        storage_actions.pack(fill="x", pady=(0, 9))
        self.storage_scan_selected_button = RoundedButton(
            storage_actions, "Analisar selecionados", self.scan_selected_volumes,
            primary=True, width=174,
        )
        self.storage_scan_selected_button.pack(side="left", padx=3)
        self.storage_scan_all_button = RoundedButton(
            storage_actions, "Analisar todos", self.scan_all_volumes, width=142,
        )
        self.storage_scan_all_button.pack(side="left", padx=3)
        ttk.Label(storage_actions, text="Os resultados aparecem na aba Resultados.",
                  style="Muted.TLabel").pack(side="left", padx=10)
        self.scan_trigger_buttons.extend((self.storage_scan_selected_button, self.storage_scan_all_button))
        storage_panel = RoundedPanel(self.storage_tab, padding=10)
        storage_panel.pack(fill="both", expand=True)
        storage_panel.content.grid_rowconfigure(0, weight=1)
        storage_panel.content.grid_columnconfigure(0, weight=1)
        self.storage_tree = ttk.Treeview(
            storage_panel.content,
            columns=("root", "label", "type", "total", "free", "status"),
            show="headings", selectmode="extended", height=9,
        )
        for column, title, width in (
            ("root", "UNIDADE", 78), ("label", "RÓTULO", 220), ("type", "TIPO", 115),
            ("total", "CAPACIDADE", 145), ("free", "LIVRE", 145), ("status", "ESTADO", 135),
        ):
            self.storage_tree.heading(column, text=title)
            self.storage_tree.column(column, width=width, minwidth=65, anchor="w",
                                     stretch=(column == "label"))
        self.storage_tree.tag_configure("unavailable", foreground="#FFC97A")
        self.storage_tree.grid(row=0, column=0, sticky="nsew")
        storage_scroll = ttk.Scrollbar(storage_panel.content, orient="vertical", command=self.storage_tree.yview)
        storage_scroll.grid(row=0, column=1, sticky="ns")
        self.storage_tree.configure(yscrollcommand=storage_scroll.set)
        self._enable_tree_sort(self.storage_tree, ("root", "label", "type", "total", "free", "status"))
        self.storage_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_volume_detail())
        self.storage_tree.bind("<Double-1>", self._open_volume_applications)
        self.storage_status = ttk.Label(self.storage_tab, text="", style="Muted.TLabel")
        self.storage_status.pack(anchor="w", padx=3, pady=(8, 3))
        self.storage_detail = self._detail(self.storage_tab)
        self.volume_by_iid = {}
        self.storage_queue = queue.Queue()
        self.storage_refreshing = False
        self.app_inventory_queue = queue.Queue()
        self.app_inventory_generation = 0
        self.app_inventory_root = None
        self.app_inventory_by_iid = {}
        self.app_inventory_tab = None
        self.app_inventory_tree = None
        self.app_inventory_detail = None
        self.app_inventory_status = None
        self.app_inventory_title = None
        self.app_inventory_refresh_button = None
        self.refresh_storage_volumes()
        self.after(100, self._poll_storage_inventory)
        self.after(100, self._poll_installed_applications)
        self.bind_all("<MouseWheel>", self._tree_mousewheel, add="+")
        self.bind_all("<Button-4>", self._tree_mousewheel, add="+")
        self.bind_all("<Button-5>", self._tree_mousewheel, add="+")

        ttk.Label(shell, padding=(2, 12, 0, 0),
                  text="Rótulos são sinais para revisão, não prova de segurança. Temporários podem ser necessários a programas em uso.",
                  style="Muted.TLabel").pack(anchor="w")

    def _make_tree(self, parent):
        panel = RoundedPanel(parent, padding=10)
        panel.pack(fill="both", expand=True)
        tree = ttk.Treeview(panel.content, columns=("risk", "size", "kind", "signature", "modified", "path"),
                            show="headings", height=10)
        columns = (("risk", "CLASSIFICAÇÃO", 135), ("size", "TAMANHO", 78),
                   ("kind", "TIPO / EXTENSÃO", 120), ("signature", "ASSINATURA", 110),
                   ("modified", "MODIFICADO", 132), ("path", "ARQUIVO", 420))
        for column, title, width in columns:
            tree.heading(column, text=title)
            tree.column(column, width=width, minwidth=160 if column == "path" else 58,
                        anchor="w", stretch=(column == "path"))
        backgrounds = {
            "Perigoso": "#4B243E", "Alto risco": "#4B243E", "Suspeito": "#4A3526",
            "Baixo risco": "#244038", "Inconclusivo": "#3A2750",
        }
        for risk, color in self.COLORS.items():
            tree.tag_configure(risk, foreground=color, background=backgrounds[risk])
        panel.content.grid_rowconfigure(0, weight=1)
        panel.content.grid_columnconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(panel.content, orient="vertical", command=tree.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        tree.configure(yscrollcommand=vertical.set)
        self._enable_tree_sort(tree, tuple(item[0] for item in columns))
        return tree

    def _build_result_filters(self, parent):
        panel = RoundedPanel(parent, padding=9, radius=16, fixed_height=68)
        panel.pack(fill="x", pady=(0, 8))
        row = tk.Frame(panel.content, bg=PANEL)
        row.pack(fill="x", expand=True)
        self.filter_risk = tk.StringVar(value="Todas")
        self._filter_combo(row, "Classificação", self.filter_risk,
                           ("Todas", "Perigoso", "Alto risco", "Suspeito", "Baixo risco", "Inconclusivo"), 20).pack(side="left")
        self.filter_count = ttk.Label(row, text="0 resultado(s)", style="Muted.TLabel")
        self.filter_count.pack(side="right", padx=(8, 4))
        self._filter_job = None
        self.filter_risk.trace_add("write", self._schedule_result_filter)

    @staticmethod
    def _filter_combo(parent, title, variable, values, width):
        holder = tk.Frame(parent, bg=PANEL)
        tk.Label(holder, text=title, bg=PANEL, fg=SECONDARY, font=("Segoe UI", 8)).pack(anchor="w")
        ttk.Combobox(holder, textvariable=variable, values=values, state="readonly", width=width).pack(fill="x", ipady=1)
        return holder

    def _schedule_result_filter(self, *_args):
        if self._filter_job:
            try: self.after_cancel(self._filter_job)
            except tk.TclError: pass
        self._filter_job = self.after(180, self._rebuild)

    def _matches_result_filters(self, finding):
        risk = self.filter_risk.get()
        if not risk or risk == "Todas": return True
        if risk == "Perigoso": return finding.manual_classification == "Perigoso"
        if risk == "Baixo risco":
            return finding.risk == risk or finding.manual_classification == risk
        return finding.risk == risk

    @staticmethod
    def _format_file_size(size):
        if size is None: return "—"
        value = float(size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024 or unit == "TB":
                return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            value /= 1024

    @staticmethod
    def _format_modified(timestamp):
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M") if timestamp is not None else "—"

    def _enable_tree_sort(self, tree, columns):
        titles = {column: tree.heading(column, "text") for column in columns}
        self.tree_heading_titles[tree] = titles
        for column in columns:
            tree.heading(column, command=lambda current=tree, col=column: self._sort_tree(current, col))

    def _sort_key(self, tree, iid, column):
        finding = self.by_iid.get(iid)
        if finding:
            attr = {"risk": "risk", "size": "size_bytes", "kind": "kind",
                    "signature": "signature", "modified": "modified_time", "path": "path"}.get(column)
            value = getattr(finding, attr, None) if attr else tree.set(iid, column)
            if column == "risk":
                return {"Perigoso": 0, "Alto risco": 0, "Suspeito": 1, "Inconclusivo": 2, "Baixo risco": 3}.get(value, 4)
            if column in ("size", "modified"): return value if value is not None else -1
            return str(value or "").casefold()
        if tree is getattr(self, "storage_tree", None) and iid in getattr(self, "volume_by_iid", {}):
            volume = self.volume_by_iid[iid]
            value = {"root": volume.root, "label": volume.label, "type": volume.drive_type,
                     "total": volume.total_bytes, "free": volume.free_bytes, "status": volume.status}.get(column)
            return value if isinstance(value, (int, float)) else str(value or "").casefold()
        if tree is getattr(self, "app_inventory_tree", None) and iid in getattr(self, "app_inventory_by_iid", {}):
            app = self.app_inventory_by_iid[iid]
            value = {
                "name": app.name, "size": app.estimated_size_bytes,
                "publisher": app.publisher, "installed": app.install_date,
                "activity": app.last_used_at,
            }.get(column)
            if column in ("size", "activity"):
                return value if value is not None else -1
            return str(value or "").casefold()
        return str(tree.set(iid, column) or "").casefold()

    def _sort_tree(self, tree, column):
        state = self.tree_sort_state.get(tree)
        reverse = not state[1] if state and state[0] == column else False
        self.tree_sort_state[tree] = (column, reverse)
        self._apply_tree_sort(tree)

    def _apply_tree_sort(self, tree):
        column, reverse = self.tree_sort_state[tree]
        items = sorted(tree.get_children(""), key=lambda iid: self._sort_key(tree, iid, column), reverse=reverse)
        for index, iid in enumerate(items): tree.move(iid, "", index)
        for col, title in self.tree_heading_titles.get(tree, {}).items():
            marker = (" ↓" if reverse else " ↑") if col == column else ""
            tree.heading(col, text=title + marker)

    def _insert_sorted(self, tree, iid):
        state = self.tree_sort_state.get(tree)
        if not state: return
        column, reverse = state
        target = self._sort_key(tree, iid, column)
        children = [item for item in tree.get_children("") if item != iid]
        low, high = 0, len(children)
        while low < high:
            middle = (low + high) // 2
            current = self._sort_key(tree, children[middle], column)
            comes_before = target > current if reverse else target < current
            if comes_before: high = middle
            else: low = middle + 1
        tree.move(iid, "", low)

    def _tree_mousewheel(self, event):
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None and widget.winfo_class() != "Treeview":
            try: widget = widget.master
            except AttributeError: return
        if widget is None: return
        if getattr(event, "num", None) in (4, 5):
            delta = -1 if event.num == 4 else 1
        else:
            delta = -1 if event.delta > 0 else 1
        widget.yview_scroll(delta * 3, "units")
        return "break"

    @staticmethod
    def _capture_tree_state(tree):
        return (tree.selection(), tree.yview()[0])

    def _restore_tree_state(self, tree, state):
        selected, y_pos = state
        available = set(tree.get_children(""))
        valid = [iid for iid in selected if iid in available]
        if valid:
            tree.selection_set(valid)
        else:
            current_selection = tree.selection()
            if current_selection: tree.selection_remove(*current_selection)
        tree.yview_moveto(y_pos)
        if valid and tree in (getattr(self, "result_tree", None), getattr(self, "danger_tree", None), getattr(self, "temp_tree", None)):
            self.show_detail(tree)
        elif valid and tree is getattr(self, "storage_tree", None):
            self.show_volume_detail()
        elif valid and tree is getattr(self, "quarantine_tree", None):
            self.show_quarantine_detail()
        elif valid and tree is getattr(self, "app_inventory_tree", None):
            self._show_installed_app_detail()
        else:
            details = {self.result_tree: self.result_detail, self.danger_tree: self.danger_detail,
                       self.temp_tree: self.temp_detail}.get(tree)
            if details: self._set_detail(details, "Selecione um item para ver os detalhes.")
            elif tree is getattr(self, "storage_tree", None):
                self._set_detail(self.storage_detail, "Selecione um ou mais volumes para ver os detalhes.")
            elif tree is getattr(self, "quarantine_tree", None):
                self._set_detail(self.quarantine_detail, "Selecione um item para ver os detalhes.")
            elif tree is getattr(self, "app_inventory_tree", None):
                self._set_detail(self.app_inventory_detail, "Selecione um aplicativo para ver os detalhes.")

    def _row(self, tree, finding):
        if tree is self.result_tree and not self._matches_result_filters(finding):
            self._update_filter_count()
            return
        label = self._risk_text(finding)
        tag = finding.risk if finding.risk in self.COLORS else "Inconclusivo"
        values = (f"● {label}", self._format_file_size(finding.size_bytes), finding.kind,
                  finding.signature, self._format_modified(finding.modified_time),
                  self._display_path(finding.path))
        iid = str(id(finding))
        if tree.exists(iid): return
        tree.insert("", "end", iid=iid, values=values, tags=(tag,))
        self._insert_sorted(tree, iid)
        if tree is self.result_tree and not getattr(self, "_batch_rebuilding", False):
            self._update_filter_count()

    @staticmethod
    @staticmethod
    def _display_path(path):
        normalized = path.rstrip("/\\")
        filename = normalized.replace("\\", "/").rsplit("/", 1)[-1]
        return filename or path

    def _update_filter_count(self):
        if hasattr(self, "filter_count"):
            self.filter_count.configure(
                text=f"{len(self.result_tree.get_children())} de {len(self.findings)} resultado(s)"
            )

    def _rebuild(self):
        self.by_iid = {str(id(finding)): finding for finding in self.findings}
        trees = (self.result_tree, self.danger_tree, self.temp_tree)
        states = {tree: self._capture_tree_state(tree) for tree in trees}
        for tree in trees: tree.delete(*tree.get_children())
        snapshot = tuple(self.findings)
        self._rebuild_generation = getattr(self, "_rebuild_generation", 0) + 1
        generation = self._rebuild_generation

        def render_batch(offset):
            if generation != self._rebuild_generation: return
            end = min(offset + REBUILD_BATCH_SIZE, len(snapshot))
            self._batch_rebuilding = True
            try:
                for finding in snapshot[offset:end]:
                    if str(id(finding)) not in self.by_iid: continue
                    self._row(self.result_tree, finding)
                    if (finding.manual_classification == "Perigoso" or finding.risk in ("Alto risco", "Suspeito")) and is_executable(finding.path):
                        self._row(self.danger_tree, finding)
                    if is_temp_candidate(finding.path): self._row(self.temp_tree, finding)
            finally:
                self._batch_rebuilding = False
            if end < len(snapshot):
                self.after(1, render_batch, end)
                return
            for tree in trees: self._restore_tree_state(tree, states[tree])
            self._update_filter_count()
            self.refresh_quarantine()

        self.after_idle(render_batch, 0)

    def show_detail(self, tree):
        finding = self._selected(tree)
        if not finding:
            widget = {self.result_tree: self.result_detail, self.danger_tree: self.danger_detail,
                      self.temp_tree: self.temp_detail}.get(tree)
            if widget: self._set_detail(widget, "Selecione um item para ver os detalhes.")
            return
        modified = self._format_modified(finding.modified_time)
        size = self._format_file_size(finding.size_bytes)
        text = (f"Caminho completo: {finding.path}\nClassificação técnica: {finding.risk}"
                f"\nDecisão manual: {finding.manual_classification or 'nenhuma'}"
                f"\nOrigem: {finding.source}\nMotivos técnicos: {finding.reasons}\nTamanho: {size}"
                f"\nModificado: {modified}\nSHA-256: {finding.sha256 or 'indisponível'}"
                f"\nAssinatura: {finding.signature}\nReputação: {finding.reputation}")
        widget = {self.result_tree: self.result_detail, self.danger_tree: self.danger_detail,
                  self.temp_tree: self.temp_detail}[tree]
        self._set_detail(widget, text)

    def _detail(self, parent):
        panel = RoundedPanel(parent, padding=8, radius=16)
        panel.pack(fill="x", pady=(0, 1))
        box = tk.Text(panel.content, height=4, bg=PANEL, fg=TEXT, insertbackground=WHITE,
                      relief="flat", bd=0, wrap="word", font=("Segoe UI", 10),
                      padx=8, pady=5, highlightthickness=0)
        box.pack(fill="x", expand=True)
        box.configure(state="disabled")
        return box

    @staticmethod
    def _format_volume_size(size):
        if size is None:
            return "—"
        value = float(size)
        for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
            if value < 1024 or unit == "PB":
                return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            value /= 1024

    @staticmethod
    def _activity_label(last_used_at):
        if last_used_at is None:
            return "Sem registro"
        try:
            age_days = max(0, (datetime.now().timestamp() - last_used_at) / 86400)
        except (OverflowError, OSError, ValueError):
            return "Data indisponível"
        return "Mais de 180 dias" if age_days >= 180 else "Uso registrado"

    def _open_volume_applications(self, event):
        iid = self.storage_tree.identify_row(event.y)
        volume = self.volume_by_iid.get(iid)
        if volume is None:
            return
        if volume.status != "Disponível":
            self.storage_status.configure(text=f"A unidade {volume.root} está indisponível para consulta.")
            return
        if self.app_inventory_tab is None:
            self.app_inventory_tab = tk.Frame(self.tabs.page_host, bg=BG)
            self.tabs.add(self.app_inventory_tab, "Aplicativos instalados")
            self._build_installed_applications_tab(self.app_inventory_tab)
        self.tabs.select(self.app_inventory_tab)
        self._load_installed_applications(volume.root)

    def _build_installed_applications_tab(self, parent):
        header = tk.Frame(parent, bg=BG)
        header.pack(fill="x", pady=(0, 7))
        self.app_inventory_title = ttk.Label(header, text="Aplicativos instalados", style="Title.TLabel")
        self.app_inventory_title.pack(side="left", padx=3)
        self.app_inventory_refresh_button = RoundedButton(
            header, "Atualizar lista", self._refresh_installed_applications, width=136,
        )
        self.app_inventory_refresh_button.pack(side="right", padx=3)
        ttk.Label(
            parent,
            text=("Lista programas registrados como instalados nesta unidade. O tamanho é uma estimativa do instalador; "
                  "a atividade depende do histórico local do Windows e pode estar incompleta."),
            style="Muted.TLabel", wraplength=1000, justify="left",
        ).pack(anchor="w", padx=3, pady=(0, 9))

        panel = RoundedPanel(parent, padding=9)
        panel.pack(fill="both", expand=True)
        panel.content.grid_rowconfigure(0, weight=1)
        panel.content.grid_columnconfigure(0, weight=1)
        columns = ("name", "size", "publisher", "installed", "activity")
        self.app_inventory_tree = ttk.Treeview(
            panel.content, columns=columns, show="headings", height=10,
        )
        for column, title, width in (
            ("name", "APLICATIVO", 260), ("size", "TAMANHO ESTIMADO", 145),
            ("publisher", "PUBLICADOR", 220), ("installed", "INST./ATUALIZAÇÃO", 165),
            ("activity", "ATIVIDADE REGISTRADA", 185),
        ):
            self.app_inventory_tree.heading(column, text=title)
            self.app_inventory_tree.column(
                column, width=width, minwidth=95, anchor="w",
                stretch=(column in ("name", "publisher")),
            )
        self.app_inventory_tree.tag_configure("old_activity", foreground="#FFC97A")
        self.app_inventory_tree.tag_configure("unknown_activity", foreground=SECONDARY)
        self.app_inventory_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(panel.content, orient="vertical", command=self.app_inventory_tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.app_inventory_tree.configure(yscrollcommand=scrollbar.set)
        self._enable_tree_sort(self.app_inventory_tree, columns)
        self.app_inventory_tree.bind("<<TreeviewSelect>>", lambda _e: self._show_installed_app_detail())
        self.app_inventory_tree.bind("<Double-1>", lambda _e: self._show_installed_app_detail())
        self.app_inventory_status = ttk.Label(parent, text="", style="Muted.TLabel", wraplength=1000)
        self.app_inventory_status.pack(anchor="w", padx=3, pady=(8, 5))
        self.app_inventory_detail = self._detail(parent)

    def _refresh_installed_applications(self):
        if self.app_inventory_root:
            self._load_installed_applications(self.app_inventory_root)

    def _load_installed_applications(self, root):
        self.app_inventory_root = root
        self.app_inventory_generation += 1
        generation = self.app_inventory_generation
        self.app_inventory_title.configure(text=f"Aplicativos instalados em {root}")
        self.app_inventory_status.configure(text="Consultando o inventário local do Windows…")
        self.app_inventory_refresh_button.configure(state="disabled")
        self.app_inventory_tree.delete(*self.app_inventory_tree.get_children())
        self.app_inventory_by_iid = {}
        self._set_detail(self.app_inventory_detail, "Nenhum aplicativo selecionado.")
        threading.Thread(
            target=self._installed_applications_worker,
            args=(root, generation), daemon=True,
        ).start()

    def _installed_applications_worker(self, root, generation):
        try:
            inventory = enumerate_installed_applications(root)
            self.app_inventory_queue.put((generation, root, inventory, ""))
        except Exception as exc:
            self.app_inventory_queue.put((generation, root, None, str(exc)))

    def _poll_installed_applications(self):
        matching = None
        while True:
            try:
                result = self.app_inventory_queue.get_nowait()
            except queue.Empty:
                break
            if result[0] == self.app_inventory_generation and result[1] == self.app_inventory_root:
                matching = result
        if matching is not None:
            _generation, _root, inventory, error = matching
            self.app_inventory_refresh_button.configure(state="normal")
            if error:
                self.app_inventory_status.configure(text=f"Não foi possível listar os aplicativos: {error}")
            else:
                self._show_installed_applications(inventory)
        self.after(100, self._poll_installed_applications)

    def _show_installed_applications(self, inventory):
        self.app_inventory_tree.delete(*self.app_inventory_tree.get_children())
        self.app_inventory_by_iid = {}
        older_count = 0
        unknown_count = 0
        for index, app in enumerate(inventory.applications):
            iid = f"app-{self.app_inventory_generation}-{index}"
            self.app_inventory_by_iid[iid] = app
            activity = self._activity_label(app.last_used_at)
            if activity == "Mais de 180 dias":
                older_count += 1
                tags = ("old_activity",)
            elif activity == "Sem registro":
                unknown_count += 1
                tags = ("unknown_activity",)
            else:
                tags = ()
            self.app_inventory_tree.insert(
                "", "end", iid=iid,
                values=(app.name, self._format_volume_size(app.estimated_size_bytes),
                        app.publisher or "—", app.install_date or "—", activity),
                tags=tags,
            )
        if self.app_inventory_tree in self.tree_sort_state:
            self._apply_tree_sort(self.app_inventory_tree)
        count = len(inventory.applications)
        activity_note = (
            "Histórico de uso local disponível, mas pode não registrar todas as formas de abertura."
            if inventory.activity_available else
            "O histórico local de uso não está disponível nesta conta do Windows."
        )
        self.app_inventory_status.configure(
            text=(f"{count} aplicativo(s) registrado(s); {older_count} com último uso registrado há mais de 180 dias; "
                  f"{unknown_count} sem registro de uso. {activity_note} "
                  f"Tamanho e data de instalação/atualização vêm dos dados informados pelos instaladores; "
                  f"{inventory.unreadable_entries} entrada(s) não puderam ser lidas.")
        )
        self._set_detail(
            self.app_inventory_detail,
            "Selecione um aplicativo. A ausência de registro de atividade não significa que ele nunca foi usado.",
        )

    def _show_installed_app_detail(self):
        selection = self.app_inventory_tree.selection() if self.app_inventory_tree else ()
        app = self.app_inventory_by_iid.get(selection[0]) if selection else None
        if app is None:
            self._set_detail(self.app_inventory_detail, "Selecione um aplicativo para ver os detalhes.")
            return
        if app.last_used_at is None:
            last_used = "Nenhum registro local encontrado; isso não confirma inatividade."
        else:
            last_used = self._format_modified(app.last_used_at)
        details = (
            f"Aplicativo: {app.name}\nPublicador: {app.publisher or 'não informado'}"
            f"\nLocal de instalação: {app.install_location}"
            f"\nTamanho estimado: {self._format_volume_size(app.estimated_size_bytes)}"
            f"\nData registrada pelo instalador (pode ser atualização): {app.install_date or 'não informada'}"
            f"\nÚltima atividade encontrada no histórico local: {last_used}"
            "\nO inventário não executa nem altera o aplicativo; revise as informações antes de qualquer ação no Windows."
        )
        self._set_detail(self.app_inventory_detail, details)

    def refresh_storage_volumes(self):
        if not hasattr(self, "storage_tree") or self.storage_refreshing:
            return
        self.storage_refreshing = True
        self.storage_status.configure(text="Atualizando volumes montados…")
        self.storage_refresh_button.configure(state="disabled")
        threading.Thread(target=self._storage_inventory_worker, daemon=True).start()

    def scan_selected_volumes(self):
        selected = self.storage_tree.selection()
        roots = [self.volume_by_iid[iid].root for iid in selected if iid in self.volume_by_iid]
        if not roots:
            messagebox.showinfo("Armazenamento", "Selecione um ou mais volumes para analisar.")
            return
        self.start_scan(roots)
        if self.scan_active:
            self.tabs.select(self.results_tab)

    def scan_all_volumes(self):
        roots = [volume.root for volume in self.volume_by_iid.values()]
        if not roots:
            messagebox.showinfo("Armazenamento", "Não há volumes montados para analisar.")
            return
        if not messagebox.askyesno(
            "Analisar todos os volumes",
            "A análise pode demorar e alcança somente arquivos acessíveis. Continuar?",
        ):
            return
        self.start_scan(roots)
        if self.scan_active:
            self.tabs.select(self.results_tab)

    def _storage_inventory_worker(self):
        try:
            volumes = enumerate_volumes()
            result = (volumes, "")
        except Exception as exc:
            result = ([], str(exc))
        self.storage_queue.put(result)

    def _poll_storage_inventory(self):
        try:
            volumes, error = self.storage_queue.get_nowait()
        except queue.Empty:
            pass
        else:
            self.storage_refreshing = False
            self.storage_refresh_button.configure(state="normal")
            if error:
                self.storage_tree.delete(*self.storage_tree.get_children())
                self.volume_by_iid = {}
                self.storage_status.configure(text=f"Não foi possível listar os volumes: {error}")
                self._set_detail(self.storage_detail, "Selecione um ou mais volumes para ver os detalhes.")
            else:
                self._show_storage_volumes(volumes)
        self.after(100, self._poll_storage_inventory)

    def _show_storage_volumes(self, volumes):
        state = self._capture_tree_state(self.storage_tree)
        if not volumes:
            self.storage_tree.delete(*self.storage_tree.get_children())
            self.volume_by_iid = {}
            self.storage_status.configure(text="Nenhum volume montado foi encontrado.")
            self._set_detail(self.storage_detail, "Selecione um ou mais volumes para ver os detalhes.")
            return
        try:
            self.storage_tree.delete(*self.storage_tree.get_children())
        except tk.TclError:
            return
        self.volume_by_iid = {}
        for volume in volumes:
            iid = volume.root
            self.volume_by_iid[iid] = volume
            values = (
                volume.root, volume.label, volume.drive_type,
                self._format_volume_size(volume.total_bytes),
                self._format_volume_size(volume.free_bytes), volume.status,
            )
            tag = "unavailable" if volume.status != "Disponível" else ""
            self.storage_tree.insert("", "end", iid=iid, values=values, tags=(tag,) if tag else ())
        if self.storage_tree in self.tree_sort_state:
            self._apply_tree_sort(self.storage_tree)
        count = len(volumes)
        self.storage_status.configure(
            text=f"{count} volume(s) montado(s) listado(s). Nenhum arquivo foi analisado."
        )
        self._restore_tree_state(self.storage_tree, state)

    def show_volume_detail(self):
        selected = [self.volume_by_iid[iid] for iid in self.storage_tree.selection()
                    if iid in self.volume_by_iid]
        if not selected:
            self._set_detail(self.storage_detail, "Selecione um ou mais volumes para ver os detalhes.")
            return
        blocks = []
        for volume in selected:
            details = (
                f"Unidade: {volume.root}\nRótulo: {volume.label}\nTipo: {volume.drive_type}"
                f"\nCapacidade: {self._format_volume_size(volume.total_bytes)}"
                f"\nEspaço livre: {self._format_volume_size(volume.free_bytes)}\nEstado: {volume.status}"
            )
            if volume.error:
                details += f"\nMotivo: {volume.error}"
            blocks.append(details)
        self._set_detail(self.storage_detail, "\n\n".join(blocks))

    def _row(self, tree, finding):
        label = self._risk_text(finding)
        tag = finding.risk if finding.risk in self.COLORS else "Inconclusivo"
        tree.insert("", "end", iid=str(id(finding)),
                    values=(f"● {label}", finding.kind, finding.signature, finding.path), tags=(tag,))

    def open_quarantine_location(self):
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            os.startfile(str(self.quarantine_dir))
        except OSError as exc:
            messagebox.showerror("Quarentena", f"Não foi possível abrir a pasta da quarentena: {exc}")

    def open_dangerous_location(self):
        finding = self._selected(self.danger_tree)
        if not finding:
            messagebox.showinfo("Localização", "Selecione um aplicativo.")
            return
        folder = os.path.dirname(os.path.abspath(finding.path))
        if not os.path.isdir(folder):
            messagebox.showerror("Localização", f"A pasta do arquivo não está disponível: {folder}")
            return
        try:
            os.startfile(folder)
        except OSError as exc:
            messagebox.showerror("Localização", f"Não foi possível abrir a pasta do arquivo: {exc}")

    def inspect_selected_source(self, tree=None):
        finding = self._selected(tree if tree is not None else self.danger_tree)
        if not finding:
            messagebox.showinfo("Inspeção de código", "Selecione um arquivo para inspecionar.")
            return
        try:
            result = inspect_source_file(finding.path)
        except OSError as exc:
            messagebox.showerror("Inspeção de código", str(exc))
            return

        dialog = tk.Toplevel(self)
        dialog.title("Inspeção estática — conteúdo não executado")
        dialog.geometry("980x720")
        dialog.minsize(760, 520)
        dialog.configure(bg=BG)
        dialog.transient(self)

        heading = ttk.Frame(dialog, padding=(20, 16, 20, 8))
        heading.pack(fill="x")
        ttk.Label(heading, text=finding.path, style="Muted.TLabel", wraplength=920,
                  justify="left").pack(anchor="w")
        summary = [f"Leitura: {result['encoding']} • {result['size_bytes']} bytes"]
        if result["truncated"]:
            summary.append("A leitura foi limitada ao primeiro 1 MiB.")
        if result["indicators"]:
            summary.append("Sinais para revisão: " + "; ".join(
                f"{item['label']} (linha {item['line']})" for item in result["indicators"]
            ))
        else:
            summary.append("Nenhum padrão desta lista foi encontrado no trecho lido; isso não comprova segurança.")
        summary.append("Os sinais são heurísticos, não confirmam vírus. O conteúdo é exibido como texto e nunca executado.")
        ttk.Label(heading, text="\n".join(summary), style="Muted.TLabel", wraplength=920,
                  justify="left").pack(anchor="w", pady=(8, 0))

        panel = RoundedPanel(dialog, padding=9)
        panel.pack(fill="both", expand=True, padx=20, pady=(4, 10))
        source_view = tk.Text(panel.content, bg=PANEL, fg=TEXT, insertbackground=WHITE,
                              relief="flat", bd=0, wrap="word", font=("Consolas", 10),
                              padx=8, pady=8, highlightthickness=0)
        scrollbar = ttk.Scrollbar(panel.content, orient="vertical", command=source_view.yview)
        source_view.configure(yscrollcommand=scrollbar.set)
        source_view.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        source_view.insert("1.0", result["text"])
        source_view.configure(state="disabled")
        RoundedButton(dialog, "Fechar", dialog.destroy, width=100).pack(anchor="e", padx=20, pady=(0, 16))

