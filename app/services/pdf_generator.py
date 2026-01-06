import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.utils import ImageReader

# --- CONFIGURACIÓN DE COLORES Y ESTILO ---
PRIMARY_COLOR = colors.HexColor("#2B88DA")
TEXT_COLOR = colors.HexColor("#333333")
LIGHT_GRAY = colors.HexColor("#F5F5F5")
BORDER_COLOR = colors.HexColor("#E0E0E0")

class PDFReportGenerator:
    def __init__(self, buffer, logo_path, company_logo_path=None, company_name=None):
        self.buffer = buffer
        self.logo_path = logo_path
        self.company_logo_path = company_logo_path
        self.company_name = company_name
        self.styles = getSampleStyleSheet()
        
        # Estilos personalizados Material Design
        self.styles.add(ParagraphStyle(
            name='MaterialTitle',
            fontSize=22,
            leading=26,
            textColor=PRIMARY_COLOR,
            fontName='Helvetica-Bold',
            spaceAfter=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='MaterialSubtitle',
            fontSize=12,
            leading=14,
            textColor=colors.gray,
            fontName='Helvetica',
            spaceAfter=20
        ))
        # Estilo para celdas de la tabla (fuente muy pequeña para que entren 19 columnas)
        self.styles.add(ParagraphStyle(
            name='CellText',
            fontSize=5.5,      # Reducido para encajar 19 columnas
            leading=6.5,
            textColor=TEXT_COLOR,
            fontName='Helvetica',
            wordWrap='CJK'     # Permite romper palabras largas si es necesario
        ))
        self.styles.add(ParagraphStyle(
            name='CellHeader',
            fontSize=6,
            leading=7,
            textColor=colors.white,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='CompanyName',
            fontSize=16,
            leading=18,
            textColor=TEXT_COLOR,
            fontName='Helvetica-Bold',
            alignment=2 # Right Alignment (TA_RIGHT=2)
        ))

    def _header_footer(self, canvas, doc):
        """Pie de página minimalista"""
        canvas.saveState()
        page_num = canvas.getPageNumber()
        text = f"Página {page_num} | Generado por IS Security Toolset"
        
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(colors.gray)
        # Posición para A4 Landscape
        width, height = landscape(A4)
        canvas.drawRightString(width - 30, 20, text)
        
        # Línea decorativa al pie
        canvas.setStrokeColor(PRIMARY_COLOR)
        canvas.setLineWidth(2)
        canvas.line(30, 35, width - 30, 35)
        
        canvas.restoreState()

    def _get_scaled_image(self, path, target_width):
        """Calcula dimensiones para no deformar la imagen"""
        try:
            img = ImageReader(path)
            iw, ih = img.getSize()
            aspect = ih / float(iw)
            return Image(path, width=target_width, height=(target_width * aspect))
        except Exception:
            return None

    def _format_value(self, value):
        """Limpia listas o valores vacíos para la tabla"""
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)
        if value is None:
            return ""
        return str(value)

    def create_cover_page(self, elements, report_title, device, vdom_list=None, filter_info=None):
        """Portada estilo Material con Doble Logo"""
        # 1. Logos Header Grid (Left: ISSEC, Right: Tenant)
        logo_data = [[None, None]]
        
        # Left Logo (ISSEC)
        if os.path.exists(self.logo_path):
            logo_img = self._get_scaled_image(self.logo_path, 2.0*inch)
            if logo_img:
                logo_img.hAlign = 'LEFT'
                logo_data[0][0] = logo_img
                
        # Right Logo (Tenant) OR Name
        if self.company_logo_path and os.path.exists(self.company_logo_path):
            tenant_img = self._get_scaled_image(self.company_logo_path, 1.5*inch)
            if tenant_img:
                tenant_img.hAlign = 'RIGHT'
                logo_data[0][1] = tenant_img
        elif self.company_name:
             # Fallback to Text
             logo_data[0][1] = Paragraph(self.company_name, self.styles['CompanyName'])
                
        # Logo Table
        logo_table = Table(logo_data, colWidths=[200, 500]) # Approx widths, can adjust
        logo_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (0,0), 'LEFT'),
            ('ALIGN', (1,0), (1,0), 'RIGHT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(logo_table)
        
        
        # 2. Títulos
        elements.append(Paragraph(report_title, self.styles['MaterialTitle']))
        elements.append(Paragraph(f"Reporte de Auditoría de Firewall - {datetime.now().strftime('%d/%m/%Y')}", self.styles['MaterialSubtitle']))
        elements.append(Spacer(1, 20))

        # 3. Ficha Técnica del Equipo (Card Style)
        site_name = device.site.nombre if device.site else 'N/A'
        
        # Format VDOMs for display
        vdom_display = 'Todos' if not vdom_list else ', '.join(vdom_list)
        
        device_data = [
            ['FICHA DEL DISPOSITIVO', ''],
            ['Nombre de Equipo', device.nombre],
            ['Ubicación / Sitio', site_name],
            ['Número de Serie', device.serial],
            ['Hostname', device.hostname or '-'],
            ['Alta Disponibilidad (HA)', 'Sí' if device.ha_habilitado else 'No'],
            ['VDOMs incluidos', vdom_display],
            ['Fecha Reporte', datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]

        device_table = Table(device_data, colWidths=[120, 200])
        device_table.setStyle(TableStyle([
            # Cabecera de la ficha
            ('BACKGROUND', (0, 0), (1, 0), PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
            ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (1, 0), 6),
            ('TOPPADDING', (0, 0), (1, 0), 6),
            
            # Cuerpo
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_COLOR),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
            ('TOPPADDING', (0, 1), (-1, -1), 4),
            
            # Bordes sutiles
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        # 4. Build Filter Table (if provided)
        filter_table = None
        if filter_info:
            filter_data = [['FILTROS APLICADOS', '']]
            for key, value in filter_info.items():
                if value:  # Only show non-empty filters
                    filter_data.append([key, str(value)])
            
            if len(filter_data) > 1:
                filter_table = Table(filter_data, colWidths=[120, 200])
                filter_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#5A5A5A')),
                    ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
                    ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (1, 0), 9),
                    ('BOTTOMPADDING', (0, 0), (1, 0), 6),
                    ('TOPPADDING', (0, 0), (1, 0), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), LIGHT_GRAY),
                    ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_COLOR),
                    ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
                    ('TOPPADDING', (0, 1), (-1, -1), 4),
                    ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
        
        # 5. Create two-column layout with both tables side by side
        if filter_table:
            # Wrap tables in a container table for side-by-side layout
            container = Table([[device_table, filter_table]], colWidths=[340, 340])
            container.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(container)
        else:
            elements.append(device_table)
        
        elements.append(PageBreak())

    def create_policy_table(self, policies):
        """Genera la tabla con las 19 columnas solicitadas"""
        
        # 1. Definición de Columnas (Display Name, JSON Key)
        columns_map = [
            ("ID", "ID"),
            ("VDOM", "VDOM"), # NEW
            ("Name", "Name"),  # A veces es "Policy" en el JSON, manejado abajo
            ("From", "From"),
            ("Users", "Users"),
            ("Groups", "Groups"),
            ("Source", "Source"),
            ("Src Addr", "Source Address"),
            ("To", "To"),
            ("Dest", "Destination"),
            ("Dst Addr", "Destination Address"),
            ("Service", "Service"),
            ("Action", "Action"),
            ("NAT", "NAT"),
            ("IP Pool", "IP Pool"),
            ("Seq Group", "Sequence Grouping"),
            ("Bytes", "Bytes"),
            ("Hits", "Hit Count"),
            ("Comments", "Comments"),
            ("Status", "Status")
        ]

        # 2. Encabezados
        # Extraemos solo los nombres para la primera fila
        headers = [Paragraph(col[0], self.styles['CellHeader']) for col in columns_map]
        data = [headers]

        # 3. Datos
        for p in policies:
            row = []
            json_data = p.raw_data if p.raw_data else {}
            
            for col_name, json_key in columns_map:
                # Lógica especial para Name/Policy
                if json_key == "Name":
                    val = json_data.get("Name") or json_data.get("Policy", "")
                elif json_key == "VDOM": # NEW
                    val = p.vdom
                else:
                    val = json_data.get(json_key, "")
                
                text_val = self._format_value(val)
                
                # Estilos condicionales dentro de la celda
                if json_key == "Action":
                    if text_val == "ACCEPT":
                        text_val = f"<font color='#2E7D32'><b>{text_val}</b></font>" # Green
                    elif text_val == "DENY":
                        text_val = f"<font color='#C62828'><b>{text_val}</b></font>" # Red
                
                if json_key == "Bytes" and text_val.startswith("0"):
                     text_val = f"<font color='#C62828'>{text_val}</font>" # Red for 0 bytes

                row.append(Paragraph(text_val, self.styles['CellText']))
            data.append(row)

        # 4. Configuración de Anchos (A4 Landscape = ~842 puntos de ancho total disponible)
        # --- CORRECCIÓN DE ANCHOS ---
        # Aumentamos ID de 20 a 30. Reducimos ligeramente Name, SrcAddr, DstAddr
        col_widths = [
            30,  # ID 
            40,  # VDOM (NEW)
            50,  # Name (Reducido de 60)
            40,  # From
            35,  # Users
            35,  # Groups
            45,  # Source
            50,  # Src Addr 
            40,  # To
            45,  # Dest
            50,  # Dst Addr 
            45,  # Service
            35,  # Action
            30,  # NAT
            40,  # IP Pool
            40,  # Seq Group (Reducido de 50)
            40,  # Bytes
            30,  # Hits
            45,  # Comments 
            40   # Status
        ]

        t = Table(data, colWidths=col_widths, repeatRows=1)
        
        t.setStyle(TableStyle([
            # Cabecera Material
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
            ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, 0), 4),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 4),
            
            # Filas
            ('VALIGN', (0, 1), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR), # Grilla muy fina
            
            # Alternancia de colores (Zebra striping) suave
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_GRAY]),
        ]))
        
        return t

    def generate(self, device, policies, report_type, title, vdom_list=None, filter_info=None):
        # Márgenes reducidos para aprovechar el espacio (Landscape A4)
        doc = SimpleDocTemplate(
            self.buffer, 
            pagesize=landscape(A4), 
            rightMargin=15, leftMargin=15, 
            topMargin=30, bottomMargin=30
        )
        elements = []

        # 1. Portada (now includes filter info)
        self.create_cover_page(elements, title, device, vdom_list, filter_info)

        # 2. Título de sección de datos
        elements.append(Paragraph(f"Detalle de Políticas ({len(policies)} registros)", self.styles['Heading2']))
        elements.append(Spacer(1, 10))

        # 3. Tabla
        if policies:
            table = self.create_policy_table(policies)
            elements.append(table)
        else:
            # Mensaje detallado cuando no hay resultados
            elements.append(Paragraph("⚠️ No se encontraron políticas con los parámetros especificados.", self.styles['Heading2']))
            elements.append(Spacer(1, 10))
            
            if filter_info:
                elements.append(Paragraph("Filtros aplicados:", self.styles['Normal']))
                elements.append(Spacer(1, 5))
                for key, value in filter_info.items():
                    if value:
                        elements.append(Paragraph(f"• <b>{key}:</b> {value}", self.styles['Normal']))
            else:
                elements.append(Paragraph("Verifique los criterios de búsqueda e intente nuevamente.", self.styles['Normal']))

        # Generar
        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
    
    def generate_device_report(self, device, vdoms, interfaces, title):
        """Generate a device summary report with interfaces and VDOMs"""
        doc = SimpleDocTemplate(
            self.buffer, 
            pagesize=landscape(A4), 
            rightMargin=15, leftMargin=15, 
            topMargin=30, bottomMargin=30
        )
        elements = []
        
        # Cover page
        vdom_names = [v.name for v in vdoms] if vdoms else []
        self.create_cover_page(elements, title, device, vdom_names)
        
        # Device System Info
        elements.append(Paragraph("Información del Sistema", self.styles['Heading2']))
        elements.append(Spacer(1, 10))
        
        config_data = device.config_data or {}
        system_info = config_data.get('system', {})
        
        sys_data = [
            ['Campo', 'Valor'],
            ['Hostname', system_info.get('hostname', device.hostname or '-')],
            ['Modelo', system_info.get('model', '-')],
            ['Firmware', system_info.get('version', '-')],
            ['Serial', device.serial],
            ['HA Status', 'Habilitado' if device.ha_habilitado else 'Deshabilitado'],
        ]
        
        sys_table = Table(sys_data, colWidths=[150, 400])
        sys_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))
        elements.append(sys_table)
        elements.append(Spacer(1, 20))
        
        # VDOMs Table
        if vdoms:
            elements.append(Paragraph(f"VDOMs ({len(vdoms)})", self.styles['Heading2']))
            elements.append(Spacer(1, 10))
            
            vdom_data = [['Nombre', 'Comentarios', 'Fecha Creación']]
            for v in vdoms:
                vdom_data.append([
                    v.name,
                    v.comments or '-',
                    v.created_at.strftime('%Y-%m-%d') if v.created_at else '-'
                ])
            
            vdom_table = Table(vdom_data, colWidths=[150, 300, 100])
            vdom_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_GRAY]),
            ]))
            elements.append(vdom_table)
            elements.append(Spacer(1, 20))
        
        # Interfaces Table
        if interfaces:
            elements.append(Paragraph(f"Interfaces ({len(interfaces)})", self.styles['Heading2']))
            elements.append(Spacer(1, 10))
            
            intf_data = [['Nombre', 'IP', 'VLAN', 'Zona', 'Estado']]
            for intf in interfaces:
                intf_data.append([
                    intf.get('name', '-'),
                    intf.get('ip', '-'),
                    str(intf.get('vlanid', '-')),
                    intf.get('zone', '-'),
                    intf.get('status', '-')
                ])
            
            intf_table = Table(intf_data, colWidths=[120, 120, 60, 100, 80])
            intf_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_GRAY]),
            ]))
            elements.append(intf_table)
        
        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
    
    def generate_history_report(self, device, sessions, title, vdom_filter=None):
        """Generate a policy change history report"""
        doc = SimpleDocTemplate(
            self.buffer, 
            pagesize=landscape(A4), 
            rightMargin=15, leftMargin=15, 
            topMargin=30, bottomMargin=30
        )
        elements = []
        
        # Cover
        vdom_list = [vdom_filter] if vdom_filter else None
        self.create_cover_page(elements, title, device, vdom_list)
        
        # Summary
        total_changes = sum(len(s.get('history_items', [])) for s in sessions)
        total_creates = sum(s.get('stats', {}).get('create', 0) for s in sessions)
        total_modifies = sum(s.get('stats', {}).get('modify', 0) for s in sessions)
        total_deletes = sum(s.get('stats', {}).get('delete', 0) for s in sessions)
        
        elements.append(Paragraph("Resumen de Cambios", self.styles['Heading2']))
        summary_data = [
            ['Métrica', 'Cantidad'],
            ['Total Sesiones de Importación', str(len(sessions))],
            ['Políticas Creadas', str(total_creates)],
            ['Políticas Modificadas', str(total_modifies)],
            ['Políticas Eliminadas', str(total_deletes)],
            ['Total Cambios', str(total_changes)],
        ]
        
        sum_table = Table(summary_data, colWidths=[200, 100])
        sum_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))
        elements.append(sum_table)
        elements.append(Spacer(1, 20))
        
        # Detail per session
        for sess in sessions:
            sess_date = sess.get('date')
            date_str = sess_date.strftime('%Y-%m-%d %H:%M') if sess_date else 'Unknown'
            
            elements.append(Paragraph(f"Importación: {date_str} - VDOM: {sess.get('vdom', 'N/A')}", self.styles['Heading3']))
            
            stats = sess.get('stats', {})
            stat_text = f"Creadas: {stats.get('create', 0)} | Modificadas: {stats.get('modify', 0)} | Eliminadas: {stats.get('delete', 0)}"
            elements.append(Paragraph(stat_text, self.styles['Normal']))
            elements.append(Spacer(1, 10))
            
            # List changes
            items = sess.get('history_items', [])
            if items:
                change_data = [['Tipo', 'Policy ID', 'VDOM', 'Cambios']]
                for item in items[:50]:  # Limit to 50 per session
                    delta = item.delta or {}
                    delta_str = ', '.join(delta.keys()) if delta else '-'
                    change_data.append([
                        item.change_type.upper(),
                        str(item.policy_uuid)[:8] + '...',
                        item.vdom or '-',
                        delta_str[:50]
                    ])
                
                ch_table = Table(change_data, colWidths=[80, 100, 80, 300])
                ch_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#666666')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
                ]))
                elements.append(ch_table)
            
            elements.append(Spacer(1, 15))
        
        
        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)

    def generate_recommendations(self, device, recommendations, title, filter_info=None):
        """Generate Detailed Recommendation Report"""
        doc = SimpleDocTemplate(
            self.buffer, 
            pagesize=landscape(A4), 
            rightMargin=15, leftMargin=15, 
            topMargin=30, bottomMargin=30
        )
        elements = []

        # 1. Cover Page
        vdoms = set(r.related_vdom for r in recommendations if r.related_vdom)
        self.create_cover_page(elements, title, device, list(vdoms), filter_info)

        # 2. Intro
        elements.append(Paragraph(f"Resumen de Hallazgos ({len(recommendations)})", self.styles['Heading2']))
        elements.append(Spacer(1, 10))

        # 3. Summary Table
        summary_data = [['Policy ID', 'Severidad', 'VDOM', 'Título']]
        for r in recommendations:
            pol_id = str(r.related_policy_id) if r.related_policy_id is not None else 'N/A'
            summary_data.append([
                pol_id,
                r.severity.upper(),
                r.related_vdom or '-',
                r.title
            ])
        
        # Calculate widths
        # A4 Landscape ~800pts
        sum_table = Table(summary_data, colWidths=[80, 80, 100, 500])
        sum_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_GRAY]),
        ]))
        elements.append(sum_table)
        elements.append(PageBreak())

        # 4. Detailed Findings
        elements.append(Paragraph("Detalle de Recomendaciones", self.styles['MaterialTitle']))
        elements.append(Spacer(1, 10))

        for i, r in enumerate(recommendations, 1):
            # Card Header
            header_color = colors.orange
            if r.severity == 'critical': header_color = colors.red
            elif r.severity == 'high': header_color = colors.orangered
            elif r.severity == 'low': header_color = colors.green
            
            # Use KeepTogether to avoid breaking a finding across pages if possible, 
            # but usually findings are long so we might not want to enforce it too strictly for long CLI.
            # We'll stick to sequential flow.
            
            elements.append(Paragraph(f"#{i} - {r.title}", self.styles['Heading3']))
            
            # Metadata Grid
            pol_id = str(r.related_policy_id) if r.related_policy_id is not None else 'N/A'
            meta_data = [
                [f"Política Relacionada: {pol_id}", f"Severidad: {r.severity.upper()}"],
                [f"VDOM: {r.related_vdom or '-'}", f"Fecha: {r.created_at.strftime('%Y-%m-%d %H:%M') if r.created_at else '-'}"],
            ]
            meta_table = Table(meta_data, colWidths=[300, 300])
            meta_table.setStyle(TableStyle([
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.gray),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('LINEBELOW', (0, -1), (-1, -1), 0.5, LIGHT_GRAY),
            ]))
            elements.append(meta_table)
            elements.append(Spacer(1, 10))

            # Content
            elements.append(Paragraph("<b>Descripción del Riesgo:</b>", self.styles['Normal']))
            elements.append(Paragraph(r.description or 'Sin descripción', self.styles['Normal']))
            elements.append(Spacer(1, 5))

            elements.append(Paragraph("<b>Acción Recomendada:</b>", self.styles['Normal']))
            elements.append(Paragraph(r.recommendation or '-', self.styles['Normal']))
            elements.append(Spacer(1, 5))
            
            # CLI Remediation
            evidence = r.evidence or {}
            cli = evidence.get('cli_remediation')
            if cli:
                elements.append(Paragraph("<b>CLI Remediation Script:</b>", self.styles['Normal']))
                # Use a monospaced style
                code_style = ParagraphStyle(
                    'Code',
                    parent=self.styles['Normal'],
                    fontName='Courier',
                    fontSize=8,
                    textColor=colors.white,
                    backColor=colors.HexColor('#2d2d2d'),
                    borderPadding=10,
                    leading=10
                )
                # Handle newlines in Paragraph by replacing \n with <br/>?
                # Actually Preformatted is better, but Paragraph with <br/> works.
                formatted_cli = cli.replace('\n', '<br/>')
                elements.append(Paragraph(formatted_cli, code_style))
            
            elements.append(Spacer(1, 20))
            elements.append(Paragraph("_" * 100, self.styles['Normal'])) # Separator
            elements.append(Spacer(1, 20))

        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)