# -*- coding: utf-8 -*-
"""
BrokenAuth Pro - Professional Broken Authentication Testing Extension
Version: 3.0 FINAL (Labels Fully Visible + CSV Export)
"""

from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IMessageEditorController
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JLabel, JTextField,
                         JButton, JMenuItem, JSplitPane, JCheckBox,
                         BoxLayout, Box, BorderFactory, SwingUtilities,
                         RowFilter, JComboBox, JOptionPane)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.event import DocumentListener
from java.awt import (BorderLayout, Font, Color, Dimension, GridLayout, FlowLayout, 
                      GradientPaint, Cursor)
from threading import Thread, Lock
import hashlib

try:
    unicode
except NameError:
    unicode = str


# ==================== UI COMPONENTS ====================

class GradientPanel(JPanel):
    def __init__(self, color1, color2):
        JPanel.__init__(self)
        self.color1 = color1
        self.color2 = color2
        self.setOpaque(False)
    
    def paintComponent(self, g):
        g2d = g
        gradient = GradientPaint(0, 0, self.color1, 0, self.getHeight(), self.color2)
        g2d.setPaint(gradient)
        g2d.fillRect(0, 0, self.getWidth(), self.getHeight())


class ModernButton(JButton):
    def __init__(self, text, bg_color, fg_color=Color.WHITE):
        JButton.__init__(self, text)
        self.setBackground(bg_color)
        self.setForeground(fg_color)
        self.setFocusPainted(False)
        self.setBorderPainted(False)
        self.setOpaque(True)
        self.setFont(Font("Segoe UI", Font.BOLD, 12))
        self.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))


class VerdictCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
        v = (value or "").upper()
        
        if v in ("VULNERABLE", "AT_RISK", "CRITICAL"):
            c.setBackground(Color(255, 235, 238))
            c.setForeground(Color(198, 40, 40))
            c.setFont(Font("Segoe UI", Font.BOLD, 11))
        elif v in ("AUTH_ENFORCED", "SAFE", "PROTECTED"):
            c.setBackground(Color(232, 245, 233))
            c.setForeground(Color(46, 125, 50))
            c.setFont(Font("Segoe UI", Font.BOLD, 11))
        elif v in ("SUSPICIOUS", "INPUT_ERROR", "ROUTING_ERROR"):
            c.setBackground(Color(255, 243, 224))
            c.setForeground(Color(230, 126, 34))
            c.setFont(Font("Segoe UI", Font.PLAIN, 11))
        elif v in ("SERVER_ERROR"):
            c.setBackground(Color(243, 229, 245))
            c.setForeground(Color(142, 36, 170))
        else:
            c.setBackground(Color.WHITE)
            c.setForeground(Color.BLACK)
        
        if isSelected:
            c.setBackground(Color(100, 181, 246))
        
        return c


class RiskScoreRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
        try:
            score = int(value)
            if score >= 80:
                c.setBackground(Color(255, 205, 210))
                c.setForeground(Color(183, 28, 28))
            elif score >= 50:
                c.setBackground(Color(255, 243, 224))
                c.setForeground(Color(230, 81, 0))
            else:
                c.setBackground(Color(232, 245, 233))
                c.setForeground(Color(27, 94, 32))
            c.setFont(Font("Segoe UI", Font.BOLD, 11))
        except:
            pass
        
        if isSelected:
            c.setBackground(Color(100, 181, 246))
        
        return c


class DocListener(DocumentListener):
    def __init__(self, on_change):
        self.on_change = on_change
    
    def insertUpdate(self, e):
        self.on_change()
    
    def removeUpdate(self, e):
        self.on_change()
    
    def changedUpdate(self, e):
        self.on_change()


class MessageEditorController(IMessageEditorController):
    def __init__(self, extender):
        self._extender = extender
        self._current_message = None
    
    def setCurrentMessage(self, msg):
        self._current_message = msg
    
    def getHttpService(self):
        if self._current_message:
            return self._current_message.get('service')
        return None
    
    def getRequest(self):
        if self._current_message:
            return self._current_message.get('request')
        return None
    
    def getResponse(self):
        if self._current_message:
            return self._current_message.get('response')
        return None


# ==================== MAIN EXTENSION ====================

SESSION_HEADERS = [
    "Authorization", "Cookie", "X-Auth-Token", "X-Session-Token",
    "X-Access-Token", "X-User-Token", "X-Csrf-Token", "X-XSRF-Token",
    "X-Requested-With", "X-Identity", "X-Session-Id", "Bearer"
]

STATIC_EXTS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".otf", ".map", ".pdf", ".mp4", ".mp3", ".zip",
    ".avi", ".mov", ".rar", ".tar", ".gz", ".bmp", ".eot", ".wasm"
)


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("BrokenAuth Pro")
        
        self.stored_data = []
        self.existing_rows = set()
        self.selected_headers = set(SESSION_HEADERS)
        self.auto_mode = False
        self._tested_pairs = set()
        self._status_counts = {}
        self._project_base_url = "-"
        self.row_info = {}
        
        self.data_lock = Lock()
        
        self.total_tests = 0
        self.vuln_count = 0
        self.safe_count = 0
        self.unknown_count = 0
        
        self._message_editor_controller = MessageEditorController(self)
        
        self.colors = {
            'primary': Color(33, 150, 243),
            'success': Color(76, 175, 80),
            'danger': Color(244, 67, 54),
            'warning': Color(255, 152, 0),
            'dark': Color(38, 50, 56),
            'light': Color(245, 245, 245),
            'gradient_start': Color(67, 160, 231),
            'gradient_end': Color(30, 136, 229)
        }
        
        self.setup_gui()
        self._callbacks.customizeUiComponent(self.main_panel)
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerHttpListener(self)
        
        print("[+] BrokenAuth Pro v3.0 FINAL - Loaded Successfully")
    
    
    def setup_gui(self):
        self.main_panel = JTabbedPane()
        self.main_panel.setFont(Font("Segoe UI", Font.BOLD, 13))
        
        self.main_panel.addTab("  Configuration  ", self.create_config_tab())
        self.main_panel.addTab("  Live Dashboard  ", self.create_dashboard_tab())
    
    
    def create_config_tab(self):
        panel = JPanel(BorderLayout())
        
        header = GradientPanel(self.colors['gradient_start'], self.colors['gradient_end'])
        header.setLayout(FlowLayout(FlowLayout.LEFT, 20, 15))
        header.setPreferredSize(Dimension(0, 60))
        
        title = JLabel("Scanner Configuration")
        title.setFont(Font("Segoe UI", Font.BOLD, 24))
        title.setForeground(Color.WHITE)
        header.add(title)
        
        panel.add(header, BorderLayout.NORTH)
        
        content = JPanel()
        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        content.setBackground(Color.WHITE)
        content.setBorder(BorderFactory.createEmptyBorder(20, 30, 20, 30))
        
        headers_section = self._create_headers_section()
        content.add(headers_section)
        content.add(Box.createRigidArea(Dimension(0, 20)))
        
        scope_section = self._create_scope_section()
        content.add(scope_section)
        content.add(Box.createRigidArea(Dimension(0, 20)))
        
        scan_section = self._create_scan_mode_section()
        content.add(scan_section)
        
        panel.add(content, BorderLayout.CENTER)
        return panel
    
    
    def _create_headers_section(self):
        section = JPanel()
        section.setLayout(BoxLayout(section, BoxLayout.Y_AXIS))
        section.setBackground(Color.WHITE)
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(self.colors['primary'], 2),
                "Session Headers to Test",
                0, 0, Font("Segoe UI", Font.BOLD, 14), self.colors['primary']
            ),
            BorderFactory.createEmptyBorder(10, 15, 15, 15)
        ))
        section.setMaximumSize(Dimension(32767, 250))
        
        info = JLabel("Select headers that should be tested for authentication bypass")
        info.setFont(Font("Segoe UI", Font.ITALIC, 11))
        info.setForeground(Color.GRAY)
        section.add(info)
        section.add(Box.createRigidArea(Dimension(0, 10)))
        
        self.check_grid = JPanel(GridLayout(0, 3, 10, 5))
        self.check_grid.setBackground(Color.WHITE)
        self.checkboxes = {}
        
        for header in SESSION_HEADERS:
            box = JCheckBox(header)
            box.setSelected(True)
            box.setBackground(Color.WHITE)
            box.setFont(Font("Segoe UI", Font.PLAIN, 11))
            self.check_grid.add(box)
            self.checkboxes[header] = box
        
        section.add(self.check_grid)
        section.add(Box.createRigidArea(Dimension(0, 10)))
        
        custom_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        custom_panel.setBackground(Color.WHITE)
        custom_panel.add(JLabel("Custom header:"))
        
        self.custom_header_field = JTextField(20)
        self.custom_header_field.setFont(Font("Segoe UI", Font.PLAIN, 11))
        custom_panel.add(self.custom_header_field)
        
        add_btn = ModernButton("Add", self.colors['primary'])
        add_btn.addActionListener(lambda e: self._add_custom_header())
        add_btn.setPreferredSize(Dimension(60, 26))
        custom_panel.add(add_btn)
        
        section.add(custom_panel)
        section.add(Box.createRigidArea(Dimension(0, 10)))
        
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        btn_panel.setBackground(Color.WHITE)
        
        sel_all = ModernButton("Select All", self.colors['success'])
        sel_all.addActionListener(lambda e: self._select_all_headers(True))
        sel_all.setPreferredSize(Dimension(100, 28))
        
        sel_none = ModernButton("Select None", self.colors['danger'])
        sel_none.addActionListener(lambda e: self._select_all_headers(False))
        sel_none.setPreferredSize(Dimension(100, 28))
        
        apply_btn = ModernButton("Apply Settings", self.colors['primary'])
        apply_btn.addActionListener(lambda e: self._apply_header_settings())
        apply_btn.setPreferredSize(Dimension(120, 28))
        
        btn_panel.add(sel_all)
        btn_panel.add(sel_none)
        btn_panel.add(Box.createHorizontalStrut(10))
        btn_panel.add(apply_btn)
        
        section.add(btn_panel)
        
        return section
    
    
    def _create_scope_section(self):
        section = JPanel()
        section.setLayout(BoxLayout(section, BoxLayout.Y_AXIS))
        section.setBackground(Color.WHITE)
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(self.colors['warning'], 2),
                "Scope & Filtering",
                0, 0, Font("Segoe UI", Font.BOLD, 14), self.colors['warning']
            ),
            BorderFactory.createEmptyBorder(10, 15, 15, 15)
        ))
        section.setMaximumSize(Dimension(32767, 120))
        
        self.exclude_static_cb = JCheckBox("Auto-exclude static files (.js, .css, images, etc.)", True)
        self.exclude_static_cb.setBackground(Color.WHITE)
        self.exclude_static_cb.setFont(Font("Segoe UI", Font.PLAIN, 11))
        section.add(self.exclude_static_cb)
        section.add(Box.createRigidArea(Dimension(0, 5)))
        
        self.test_only_with_headers_cb = JCheckBox("Test only endpoints with session headers", True)
        self.test_only_with_headers_cb.setBackground(Color.WHITE)
        self.test_only_with_headers_cb.setFont(Font("Segoe UI", Font.PLAIN, 11))
        section.add(self.test_only_with_headers_cb)
        
        return section
    
    
    def _create_scan_mode_section(self):
        section = JPanel()
        section.setLayout(BoxLayout(section, BoxLayout.Y_AXIS))
        section.setBackground(Color.WHITE)
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(self.colors['success'], 2),
                "Scan Mode",
                0, 0, Font("Segoe UI", Font.BOLD, 14), self.colors['success']
            ),
            BorderFactory.createEmptyBorder(10, 15, 15, 15)
        ))
        section.setMaximumSize(Dimension(32767, 150))
        
        info = JLabel("Enable auto-scan to test all Proxy/Repeater traffic automatically")
        info.setFont(Font("Segoe UI", Font.ITALIC, 11))
        info.setForeground(Color.GRAY)
        section.add(info)
        section.add(Box.createRigidArea(Dimension(0, 15)))
        
        self.auto_toggle = JCheckBox("Enable Auto-Scan (Proxy + Repeater)")
        self.auto_toggle.setBackground(Color.WHITE)
        self.auto_toggle.setFont(Font("Segoe UI", Font.BOLD, 12))
        self.auto_toggle.addActionListener(lambda e: self._toggle_auto_scan())
        section.add(self.auto_toggle)
        section.add(Box.createRigidArea(Dimension(0, 10)))
        
        self.scan_status_label = JLabel("Status: Ready (Manual mode)")
        self.scan_status_label.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.scan_status_label.setForeground(Color.GRAY)
        section.add(self.scan_status_label)
        
        return section
    
    
    def create_dashboard_tab(self):
        panel = JPanel(BorderLayout())
        
        header = GradientPanel(self.colors['gradient_start'], self.colors['gradient_end'])
        header.setLayout(FlowLayout(FlowLayout.LEFT, 20, 15))
        header.setPreferredSize(Dimension(0, 60))
        
        title = JLabel("Live Testing Dashboard")
        title.setFont(Font("Segoe UI", Font.BOLD, 24))
        title.setForeground(Color.WHITE)
        header.add(title)
        
        header.add(Box.createHorizontalStrut(30))
        
        self.scan_counter = JLabel("Scanned: 0")
        self.scan_counter.setFont(Font("Segoe UI", Font.BOLD, 14))
        self.scan_counter.setForeground(Color.WHITE)
        header.add(self.scan_counter)
        
        panel.add(header, BorderLayout.NORTH)
        
        content = JPanel(BorderLayout())
        content.setBackground(Color.WHITE)
        
        # STAT CARDS - HEIGHT 130px FOR FULL LABEL VISIBILITY
        stats_panel = JPanel(GridLayout(1, 4, 12, 0))
        stats_panel.setBackground(Color.WHITE)
        stats_panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))
        stats_panel.setPreferredSize(Dimension(0, 130))
        stats_panel.setMinimumSize(Dimension(0, 130))
        stats_panel.setMaximumSize(Dimension(32767, 130))
        
        self.total_card = self._create_stat_card("Total", "0", self.colors['primary'])
        self.vuln_card = self._create_stat_card("Vulnerable", "0", self.colors['danger'])
        self.safe_card = self._create_stat_card("Safe", "0", self.colors['success'])
        self.unknown_card = self._create_stat_card("Unknown", "0", self.colors['warning'])
        
        stats_panel.add(self.total_card)
        stats_panel.add(self.vuln_card)
        stats_panel.add(self.safe_card)
        stats_panel.add(self.unknown_card)
        
        content.add(stats_panel, BorderLayout.NORTH)
        
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split.setDividerLocation(340)
        split.setResizeWeight(0.55)
        
        table_panel = JPanel(BorderLayout())
        table_panel.setBackground(Color.WHITE)
        
        filter_panel = self._create_filter_panel()
        table_panel.add(filter_panel, BorderLayout.NORTH)
        
        self.dashboard_model = DefaultTableModel(
            ["Endpoint", "Method", "Mode", "Status", "Verdict", "Risk", "Details"], 0
        )
        self.dashboard_table = JTable(self.dashboard_model)
        self.dashboard_table.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.dashboard_table.setRowHeight(26)
        self.dashboard_table.setSelectionBackground(self.colors['primary'])
        self.dashboard_table.getTableHeader().setFont(Font("Segoe UI", Font.BOLD, 11))
        
        self.dashboard_table.getColumnModel().getColumn(4).setCellRenderer(VerdictCellRenderer())
        self.dashboard_table.getColumnModel().getColumn(5).setCellRenderer(RiskScoreRenderer())
        self.dashboard_table.getColumnModel().getColumn(0).setPreferredWidth(280)
        self.dashboard_table.getColumnModel().getColumn(6).setPreferredWidth(200)
        
        self.dashboard_sorter = TableRowSorter(self.dashboard_model)
        self.dashboard_table.setRowSorter(self.dashboard_sorter)
        self.dashboard_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_dashboard_selection()
        )
        
        scroll = JScrollPane(self.dashboard_table)
        table_panel.add(scroll, BorderLayout.CENTER)
        
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 8))
        btn_panel.setBackground(Color.WHITE)
        btn_panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color(220, 220, 220)))
        
        refresh_btn = ModernButton("Refresh", self.colors['primary'])
        refresh_btn.addActionListener(lambda e: self._refresh_dashboard())
        refresh_btn.setPreferredSize(Dimension(90, 28))
        
        clear_btn = ModernButton("Clear All", self.colors['danger'])
        clear_btn.addActionListener(lambda e: self._clear_dashboard())
        clear_btn.setPreferredSize(Dimension(90, 28))
        
        export_csv_btn = ModernButton("Export CSV", self.colors['success'])
        export_csv_btn.addActionListener(lambda e: self._export_csv())
        export_csv_btn.setPreferredSize(Dimension(100, 28))
        
        btn_panel.add(refresh_btn)
        btn_panel.add(clear_btn)
        btn_panel.add(export_csv_btn)
        
        table_panel.add(btn_panel, BorderLayout.SOUTH)
        
        viewer_panel = self._create_message_viewer()
        
        split.setTopComponent(table_panel)
        split.setBottomComponent(viewer_panel)
        
        content.add(split, BorderLayout.CENTER)
        panel.add(content, BorderLayout.CENTER)
        
        return panel
    
    
    def _create_filter_panel(self):
        panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 8))
        panel.setBackground(Color.WHITE)
        panel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color(220, 220, 220)))
        
        filter_label = JLabel("Filters:")
        filter_label.setFont(Font("Segoe UI", Font.BOLD, 11))
        panel.add(filter_label)
        
        panel.add(JLabel("Method:"))
        self.method_filter = JComboBox(["All", "GET", "POST", "PUT", "DELETE", "PATCH"])
        self.method_filter.addActionListener(lambda e: self._apply_filters())
        self.method_filter.setPreferredSize(Dimension(90, 24))
        panel.add(self.method_filter)
        
        panel.add(JLabel("Verdict:"))
        self.verdict_filter = JComboBox(["All", "VULNERABLE", "SAFE", "SUSPICIOUS"])
        self.verdict_filter.addActionListener(lambda e: self._apply_filters())
        self.verdict_filter.setPreferredSize(Dimension(120, 24))
        panel.add(self.verdict_filter)
        
        panel.add(JLabel("Search:"))
        self.search_field = JTextField(18)
        self.search_field.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.search_field.getDocument().addDocumentListener(DocListener(lambda: self._apply_filters()))
        panel.add(self.search_field)
        
        reset_btn = ModernButton("Reset", self.colors['primary'])
        reset_btn.addActionListener(lambda e: self._reset_filters())
        reset_btn.setPreferredSize(Dimension(65, 24))
        panel.add(reset_btn)
        
        return panel
    
    
    def _create_message_viewer(self):
        panel = JPanel(BorderLayout())
        panel.setBackground(Color.WHITE)
        
        viewer_header = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        viewer_header.setBackground(Color(250, 250, 250))
        viewer_header.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, Color(220, 220, 220)))
        
        viewer_title = JLabel("Request & Response Viewer")
        viewer_title.setFont(Font("Segoe UI", Font.BOLD, 12))
        viewer_header.add(viewer_title)
        
        panel.add(viewer_header, BorderLayout.NORTH)
        
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split.setDividerLocation(0.5)
        split.setResizeWeight(0.5)
        
        self._request_viewer = self._callbacks.createMessageEditor(self._message_editor_controller, False)
        self._response_viewer = self._callbacks.createMessageEditor(self._message_editor_controller, False)
        
        req_panel = JPanel(BorderLayout())
        req_header = JLabel("  REQUEST", 10)
        req_header.setFont(Font("Segoe UI", Font.BOLD, 10))
        req_header.setOpaque(True)
        req_header.setBackground(Color(240, 240, 240))
        req_header.setPreferredSize(Dimension(0, 22))
        req_panel.add(req_header, BorderLayout.NORTH)
        req_panel.add(self._request_viewer.getComponent(), BorderLayout.CENTER)
        
        resp_panel = JPanel(BorderLayout())
        resp_header = JLabel("  RESPONSE", 10)
        resp_header.setFont(Font("Segoe UI", Font.BOLD, 10))
        resp_header.setOpaque(True)
        resp_header.setBackground(Color(240, 240, 240))
        resp_header.setPreferredSize(Dimension(0, 22))
        resp_panel.add(resp_header, BorderLayout.NORTH)
        resp_panel.add(self._response_viewer.getComponent(), BorderLayout.CENTER)
        
        split.setLeftComponent(req_panel)
        split.setRightComponent(resp_panel)
        
        panel.add(split, BorderLayout.CENTER)
        
        return panel
    
    
    def _create_stat_card(self, title, value, color):
        """STAT CARD WITH LABELS FULLY VISIBLE"""
        card = JPanel()
        card.setLayout(BoxLayout(card, BoxLayout.Y_AXIS))
        card.setBackground(Color.WHITE)
        card.setBorder(BorderFactory.createLineBorder(color, 2))
        
        card.add(Box.createVerticalStrut(20))
        
        value_label = JLabel(value, 0)
        value_label.setFont(Font("Segoe UI", Font.BOLD, 34))
        value_label.setForeground(color)
        value_label.setAlignmentX(0.5)
        card.add(value_label)
        
        card.add(Box.createVerticalStrut(10))
        
        title_label = JLabel(title, 0)
        title_label.setFont(Font("Segoe UI", Font.BOLD, 14))
        title_label.setForeground(Color.GRAY)
        title_label.setAlignmentX(0.5)
        card.add(title_label)
        
        card.add(Box.createVerticalStrut(20))
        
        card.putClientProperty("value_label", value_label)
        return card
    
    
    # ==================== CORE TESTING ====================
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.auto_mode or not messageIsRequest:
            return
        
        if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER:
            Thread(target=lambda: self.scan_with_modes(messageInfo)).start()
    
    
    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages:
            menu = JMenuItem("Send to BrokenAuth Pro")
            menu.addActionListener(lambda e: self._manual_test(messages))
            return [menu]
        return []
    
    
    def _manual_test(self, messages):
        print("[+] Manual test: Processing %d selected messages" % len(messages))
        for i, msg in enumerate(messages):
            print("[+] Processing message %d/%d" % (i+1, len(messages)))
            try:
                Thread(target=lambda m=msg: self.scan_with_modes(m)).start()
            except Exception as ex:
                print("[-] Error processing message %d: %s" % (i+1, str(ex)))
        print("[+] All messages queued for testing")
    
    
    def scan_with_modes(self, messageInfo):
        try:
            req_info = self._helpers.analyzeRequest(messageInfo)
            headers = list(req_info.getHeaders())
            body = messageInfo.getRequest()[req_info.getBodyOffset():]
            url_obj = req_info.getUrl()
            url = str(url_obj)
            method = req_info.getMethod()
            
            if self.exclude_static_cb.isSelected() and self._is_static(url):
                return
            
            selected_lower = set([h.lower() for h in self.selected_headers])
            present = []
            for h in headers:
                name = h.split(":", 1)[0].strip()
                if name.lower() in selected_lower:
                    present.append(name)
            
            present_norm = sorted(list(set([n.lower() for n in present])))
            
            if self.test_only_with_headers_cb.isSelected() and not present_norm:
                return
            
            try:
                base = url_obj.getProtocol() + "://" + url_obj.getHost()
                self._project_base_url = base
            except:
                pass
            
            baseline_bytes = None
            baseline_status = -1
            try:
                resp = messageInfo.getResponse()
                if resp:
                    baseline_bytes = resp
                    info = self._helpers.analyzeResponse(resp)
                    baseline_status = info.getStatusCode()
            except:
                pass
            
            if not baseline_bytes:
                try:
                    base_resp = self._callbacks.makeHttpRequest(
                        messageInfo.getHttpService(), 
                        messageInfo.getRequest()
                    )
                    baseline_bytes = base_resp.getResponse()
                    info = self._helpers.analyzeResponse(baseline_bytes)
                    baseline_status = info.getStatusCode()
                except:
                    pass
            
            header_key = ",".join(present_norm)
            
            removed_headers = self._remove_all_session_headers(headers, present_norm)
            self.send_test(url, removed_headers, body, messageInfo,
                          "Removed All", header_key, len(present_norm) > 0,
                          baseline_status, baseline_bytes, method)
            
            stripped_headers = self._strip_all_session_headers(headers, present_norm)
            self.send_test(url, stripped_headers, body, messageInfo,
                          "Stripped All", header_key, len(present_norm) > 0,
                          baseline_status, baseline_bytes, method)
            
        except Exception as ex:
            print("[-] Scan error: " + str(ex))
    
    
    def send_test(self, url, headers, body, messageInfo, mode, header_name,
                  had_headers, baseline_status, baseline_bytes, method):
        
        try:
            body_str = self._helpers.bytesToString(body) if body else ""
            body_hash = hashlib.md5(body_str.encode('utf-8')).hexdigest()[:16]
        except:
            body_hash = str(len(body)) if body else "0"
        
        svc = messageInfo.getHttpService()
        row_id = (svc.getProtocol(), svc.getHost(), svc.getPort(), 
                  method, url, mode, body_hash)
        
        with self.data_lock:
            if row_id in self.existing_rows:
                print("[SKIP] Duplicate: %s %s (Mode: %s)" % (method, url[:60], mode))
                return
            self.existing_rows.add(row_id)
        
        new_request = self._helpers.buildHttpMessage(headers, body)
        
        def do_test():
            try:
                response = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), new_request)
                mut_bytes = response.getResponse()
                mut_info = self._helpers.analyzeResponse(mut_bytes)
                mut_status = mut_info.getStatusCode()
                mut_headers = mut_info.getHeaders()
                
                mut_ct = ""
                for h in mut_headers:
                    if h.lower().startswith("content-type:"):
                        mut_ct = h.split(":", 1)[1].strip().lower()
                        break
                
                verdict, confidence = self._calculate_verdict(
                    mut_status, method, url, mut_ct, had_headers, mut_headers
                )
                
                risk_score = self._calculate_risk_score(verdict, method, url)
                
                with self.data_lock:
                    self.total_tests += 1
                    if verdict in ("VULNERABLE", "AT_RISK", "CRITICAL"):
                        self.vuln_count += 1
                    elif verdict in ("AUTH_ENFORCED", "SAFE", "PROTECTED"):
                        self.safe_count += 1
                    else:
                        self.unknown_count += 1
                    
                    self._status_counts[mut_status] = self._status_counts.get(mut_status, 0) + 1
                    
                    result = {
                        'url': url,
                        'method': method,
                        'mode': mode,
                        'status': mut_status,
                        'verdict': verdict,
                        'risk_score': risk_score,
                        'confidence': confidence,
                        'had_headers': had_headers,
                        'baseline_status': baseline_status,
                        'details': self._generate_details(verdict, mut_status, baseline_status),
                        'request': new_request,
                        'response': mut_bytes,
                        'service': messageInfo.getHttpService()
                    }
                    self.stored_data.append(result)
                    row_idx = len(self.stored_data) - 1
                    self.row_info[row_idx] = result
                
                SwingUtilities.invokeLater(lambda: self._add_dashboard_row(result))
                SwingUtilities.invokeLater(lambda: self._update_stats())
                
            except Exception as ex:
                print("[-] Test error: " + str(ex))
        
        Thread(target=do_test).start()
    
    
    def _calculate_verdict(self, status, method, url, content_type, had_headers, headers):
        if self._is_static_content(url, content_type):
            return ("NOT_VULNERABLE_STATIC", 95)
        
        if 200 <= status < 300:
            if had_headers:
                return ("VULNERABLE", 95)
            else:
                return ("NOT_VULNERABLE_EXPECTED_2XX", 90)
        
        if status in [301, 302, 303, 307, 308]:
            redirect_location = ""
            for h in headers:
                if h.lower().startswith("location:"):
                    redirect_location = h.split(":", 1)[1].strip().lower()
                    break
            
            if any(kw in redirect_location for kw in ['/login', '/signin', '/auth', 'login?']):
                return ("AUTH_ENFORCED", 90)
            else:
                return ("SUSPICIOUS", 70)
        
        if status in [401, 403]:
            return ("AUTH_ENFORCED", 90)
        
        if status in [400, 409, 422]:
            return ("INPUT_ERROR", 80)
        
        if status in [404, 405]:
            return ("ROUTING_ERROR", 80)
        
        if status >= 500:
            return ("SERVER_ERROR", 75)
        
        return ("UNKNOWN", 60)
    
    
    def _calculate_risk_score(self, verdict, method, url_path):
        base = 0
        
        if verdict in ("VULNERABLE", "CRITICAL"):
            base = 90
        elif verdict == "AT_RISK":
            base = 80
        elif verdict == "SUSPICIOUS":
            base = 60
        elif verdict in ("AUTH_ENFORCED", "SAFE", "PROTECTED"):
            base = 10
        else:
            base = 50
        
        sensitive_keywords = ['admin', 'payment', 'delete', 'transfer', 
                             'user', 'account', 'password', 'api']
        url_lower = url_path.lower()
        for kw in sensitive_keywords:
            if kw in url_lower:
                base = min(base + 5, 100)
                break
        
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            base = min(base + 5, 100)
        
        return min(base, 100)
    
    
    def _generate_details(self, verdict, mut_status, base_status):
        if verdict == "VULNERABLE":
            return "Auth bypass detected! Status %d (baseline: %s)" % (mut_status, base_status)
        elif verdict == "AUTH_ENFORCED":
            return "Access properly blocked with %d" % mut_status
        elif verdict == "SUSPICIOUS":
            return "Unexpected behavior - manual review needed (Status: %d)" % mut_status
        else:
            return "Status: %d" % mut_status
    
    
    def _is_static(self, url):
        url_lower = url.lower()
        for ext in STATIC_EXTS:
            if url_lower.endswith(ext):
                return True
        return False
    
    
    def _is_static_content(self, url, content_type):
        if self._is_static(url):
            return True
        
        if content_type:
            static_types = ['text/css', 'application/javascript', 'image/', 'font/']
            for st in static_types:
                if content_type.startswith(st):
                    return True
        
        return False
    
    
    def _remove_all_session_headers(self, headers, present_names):
        lower = set([n.lower() for n in present_names])
        return [h for h in headers if h.split(":", 1)[0].strip().lower() not in lower]
    
    
    def _strip_all_session_headers(self, headers, present_names):
        lower = set([n.lower() for n in present_names])
        out = []
        for h in headers:
            name = h.split(":", 1)[0].strip()
            if name.lower() in lower:
                out.append(name + ":")
            else:
                out.append(h)
        return out
    
    
    # ==================== UI UPDATES ====================
    
    def _add_dashboard_row(self, result):
        self.dashboard_model.addRow([
            result['url'],
            result['method'],
            result['mode'],
            str(result['status']),
            result['verdict'],
            str(result['risk_score']),
            result['details']
        ])
        
        self.scan_counter.setText("Scanned: " + str(self.total_tests))
    
    
    def _update_stats(self):
        self._update_stat_card(self.total_card, str(self.total_tests))
        self._update_stat_card(self.vuln_card, str(self.vuln_count))
        self._update_stat_card(self.safe_card, str(self.safe_count))
        self._update_stat_card(self.unknown_card, str(self.unknown_count))
    
    
    def _update_stat_card(self, card, value):
        label = card.getClientProperty("value_label")
        if label:
            label.setText(value)
    
    
    def _on_dashboard_selection(self):
        row = self.dashboard_table.getSelectedRow()
        if row >= 0:
            model_row = self.dashboard_table.convertRowIndexToModel(row)
            if model_row < len(self.stored_data):
                result = self.stored_data[model_row]
                
                self._message_editor_controller.setCurrentMessage({
                    'request': result.get('request'),
                    'response': result.get('response'),
                    'service': result.get('service')
                })
                
                if result.get('request'):
                    self._request_viewer.setMessage(result['request'], True)
                if result.get('response'):
                    self._response_viewer.setMessage(result['response'], False)
    
    
    def _refresh_dashboard(self):
        self.dashboard_model.setRowCount(0)
        
        with self.data_lock:
            for result in self.stored_data:
                self.dashboard_model.addRow([
                    result['url'],
                    result['method'],
                    result['mode'],
                    str(result['status']),
                    result['verdict'],
                    str(result['risk_score']),
                    result['details']
                ])
        
        self._update_stats()
    
    
    def _clear_dashboard(self):
        confirm = JOptionPane.showConfirmDialog(
            self.main_panel,
            "Clear all %d test results?" % self.total_tests,
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        
        if confirm == JOptionPane.YES_OPTION:
            with self.data_lock:
                self.stored_data = []
                self.existing_rows.clear()
                self.row_info = {}
                self._tested_pairs.clear()
                self._status_counts = {}
                self.total_tests = 0
                self.vuln_count = 0
                self.safe_count = 0
                self.unknown_count = 0
            
            self.dashboard_model.setRowCount(0)
            self._update_stats()
            self.scan_counter.setText("Scanned: 0")
            
            self._request_viewer.setMessage(None, True)
            self._response_viewer.setMessage(None, False)
            
            print("[+] Dashboard cleared")
    
    
    def _apply_filters(self):
        filters = []
        
        method = self.method_filter.getSelectedItem()
        if method != "All":
            filters.append(RowFilter.regexFilter(method, 1))
        
        verdict = self.verdict_filter.getSelectedItem()
        if verdict != "All":
            filters.append(RowFilter.regexFilter(verdict, 4))
        
        search = self.search_field.getText().strip()
        if search:
            filters.append(RowFilter.regexFilter("(?i)" + search, 0))
        
        if filters:
            from javax.swing.RowFilter import andFilter
            self.dashboard_sorter.setRowFilter(andFilter(filters))
        else:
            self.dashboard_sorter.setRowFilter(None)
    
    
    def _reset_filters(self):
        self.method_filter.setSelectedIndex(0)
        self.verdict_filter.setSelectedIndex(0)
        self.search_field.setText("")
        self.dashboard_sorter.setRowFilter(None)
    
    
    # ==================== CONFIG ACTIONS ====================
    
    def _add_custom_header(self):
        name = self.custom_header_field.getText().strip()
        if not name:
            return
        
        if name in self.checkboxes:
            JOptionPane.showMessageDialog(self.main_panel, "Header already exists!")
            return
        
        box = JCheckBox(name)
        box.setSelected(True)
        box.setBackground(Color.WHITE)
        box.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.check_grid.add(box)
        self.checkboxes[name] = box
        self.check_grid.revalidate()
        self.check_grid.repaint()
        
        self.custom_header_field.setText("")
        print("[+] Added custom header: " + name)
    
    
    def _select_all_headers(self, state):
        for box in self.checkboxes.values():
            box.setSelected(state)
    
    
    def _apply_header_settings(self):
        self.selected_headers = set()
        for name, box in self.checkboxes.items():
            if box.isSelected():
                self.selected_headers.add(name)
        
        print("[+] Applied settings: %d headers selected" % len(self.selected_headers))
        JOptionPane.showMessageDialog(
            self.main_panel,
            "Settings applied! Testing with %d headers." % len(self.selected_headers),
            "Success",
            JOptionPane.INFORMATION_MESSAGE
        )
    
    
    def _toggle_auto_scan(self):
        self.auto_mode = self.auto_toggle.isSelected()
        
        if self.auto_mode:
            self.scan_status_label.setText("Status: Auto-Scan ACTIVE")
            self.scan_status_label.setForeground(self.colors['success'])
            print("[+] Auto-scan enabled")
        else:
            self.scan_status_label.setText("Status: Ready (Manual mode)")
            self.scan_status_label.setForeground(Color.GRAY)
            print("[+] Auto-scan disabled")
    
    
    def _export_csv(self):
        try:
            import codecs
            from java.lang import System
            
            path = System.getProperty("user.home") + "/brokenauth_results.csv"
            out = codecs.open(path, "w", "utf-8")
            
            out.write(u"Endpoint,Method,Mode,Status,Verdict,Risk,Details\n")
            
            with self.data_lock:
                for result in self.stored_data:
                    row = u"%s,%s,%s,%d,%s,%d,%s\n" % (
                        result['url'].replace(",", " "),
                        result['method'],
                        result['mode'].replace(",", " "),
                        result['status'],
                        result['verdict'],
                        result['risk_score'],
                        result['details'].replace(",", " ").replace("\n", " ")
                    )
                    out.write(row)
            
            out.close()
            
            JOptionPane.showMessageDialog(
                self.main_panel,
                "CSV exported successfully to:\n" + path,
                "Export Complete",
                JOptionPane.INFORMATION_MESSAGE
            )
            print("[+] Exported CSV to: " + path)
            
        except Exception as ex:
            JOptionPane.showMessageDialog(
                self.main_panel,
                "Export failed: " + str(ex),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
            print("[-] CSV export error: " + str(ex))
    
    
    # ==================== BURP INTERFACE ====================
    
    def getTabCaption(self):
        return "BrokenAuth Pro"
    
    def getUiComponent(self):
        return self.main_panel