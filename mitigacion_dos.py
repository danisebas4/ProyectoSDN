from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class AntiDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AntiDoSController, self).__init__(*args, **kwargs)
        self.blocked_ips = {}  # IPs bloqueadas con timestamp
        self.icmp_tracker = {}  # Rastreo de paquetes ICMP
        self.bandera = True  # Control de alertas por correo

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Configura el switch en modo híbrido."""
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Permitir switching normal
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 0, match, actions)

        # Copiar paquetes TCP SYN y ICMP sospechosos al controlador
        self.monitor_traffic(datapath)

    def monitor_traffic(self, datapath):
        """Copia tráfico sospechoso al controlador sin interrumpir el tráfico normal."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Copiar TCP SYN al controlador
        match_syn = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=0x02)
        actions_syn = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, max_len=128)]
        self.add_flow(datapath, 10, match_syn, actions_syn)

        # Copiar ICMP al controlador (pero permitirlo)
        match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions_icmp = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, max_len=128),
                        parser.OFPActionOutput(ofproto.OFPP_NORMAL)]  # Permitir tráfico ICMP normal
        self.add_flow(datapath, 10, match_icmp, actions_icmp)

        self.logger.info("Monitoreo de tráfico activado")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Instala reglas en el switch."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                     match=match, instructions=instructions)
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Analiza paquetes TCP SYN e ICMP sin interrumpir el tráfico normal."""
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if ip_pkt:
            src_ip = ip_pkt.src
            tipo_ataque = ""

            if tcp_pkt and tcp_pkt.bits == 0x02:  # TCP SYN
                self.logger.info(f"Posible SYN Flood detectado desde {src_ip}")
                tipo_ataque = f"SYN Flood detectado desde {src_ip}"
                self.block_ip(datapath, src_ip)

            if icmp_pkt and not self.track_icmp(src_ip):  # ICMP Flood
                self.logger.info(f"Posible ICMP Flood detectado desde {src_ip}")
                tipo_ataque = f"ICMP Flood detectado desde {src_ip}"
                self.block_ip(datapath, src_ip)

            if tipo_ataque and self.bandera:
                self.set_email(tipo_ataque)
                self.bandera = False  # Evita enviar demasiados correos

        # Llamar a la función para desbloquear IPs periódicamente
        self.unblock_ips()

    def block_ip(self, datapath, ip):
        """Bloquea una dirección IP y la desbloquea después de 60 segundos."""
        if ip in self.blocked_ips:
            self.logger.info(f"IP {ip} ya está bloqueada. Ignorando.")
            return  # No bloquear la misma IP repetidamente

        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        actions = []  # No acciones, descartar paquetes
        self.add_flow(datapath, 20, match, actions)
        self.blocked_ips[ip] = time.time()  # Guardar el tiempo de bloqueo
        self.logger.info(f"Bloqueando IP {ip} por 60 segundos")

    def unblock_ips(self):
        """Desbloquea IPs después de 60 segundos."""
        current_time = time.time()
        to_unblock = [ip for ip, timestamp in self.blocked_ips.items() if current_time - timestamp > 60]

        for ip in to_unblock:
            del self.blocked_ips[ip]  # Eliminar IP de la lista de bloqueados
            self.logger.info(f"Desbloqueando IP {ip}")

    def track_icmp(self, src_ip):
        """Rastrea el número de paquetes ICMP en 1 segundo."""
        current_time = time.time()
        if src_ip not in self.icmp_tracker:
            self.icmp_tracker[src_ip] = []
        self.icmp_tracker[src_ip].append(current_time)

        # Filtrar paquetes ICMP antiguos (más de 1 segundo)
        self.icmp_tracker[src_ip] = [t for t in self.icmp_tracker[src_ip] if current_time - t < 1]

        # Aumentar el umbral a 20 paquetes por segundo
        return len(self.icmp_tracker[src_ip]) <= 20

    def set_email(self, mensaje):
        """Envía una alerta por correo."""
        self.logger.info("Enviando notificación por correo")


        correo = "your_email"
        password = "your_password"
        destinatario = "dest_email"

        msg = MIMEMultipart()
        msg['From'] = correo
        msg['To'] = destinatario
        msg['Subject'] = "DETECCIÓN DE ANOMALÍA EN LA RED"
        msg.attach(MIMEText(mensaje, 'plain'))

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(correo, password)
                server.sendmail(correo, destinatario, msg.as_string())
            self.logger.info("Correo enviado exitosamente")
        except Exception as e:
            self.logger.error(f"Error al enviar correo: {e}")
