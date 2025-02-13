from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class AntiSpoofingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AntiSpoofingController, self).__init__(*args, **kwargs)
        self.arp_table = {}  # Tabla ARP con IP-MAC legítimas
        self.blocked_macs = set()  # MACs bloqueadas

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Configura reglas para permitir tráfico normal y enviar paquetes ARP al controlador."""
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Permitir el tráfico normal sin intervención del controlador
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 0, match, actions)

        # Regla específica: Enviar todos los paquetes ARP al controlador
        match_arp = parser.OFPMatch(eth_type=0x0806)  # ARP
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 10, match_arp, actions_arp)

        self.logger.info("Switch conectado")

    def add_flow(self, datapath, priority, match, actions):
        """Instala reglas de flujo en el switch."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=instructions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Maneja paquetes ARP recibidos por el controlador."""
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        if not arp_pkt:
            return  # Solo procesar ARP

        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac

        #self.logger.info(f"Recibido ARP: IP={src_ip}, MAC={src_mac}")

        if src_ip in self.arp_table:
            # Verificar si la MAC coincide con la registrada
            if self.arp_table[src_ip] != src_mac:
                self.logger.warning(f"¡ARP Spoofing detectado! IP={src_ip} debería ser {self.arp_table[src_ip]}, pero se recibió {src_mac}")
                self.block_mac(datapath, src_mac)
                self.send_email(f"¡ARP Spoofing detectado! IP={src_ip} debería ser {self.arp_table[src_ip]}, pero se recibió {src_mac}")
                return
        else:
            # Aprender nueva asignación IP-MAC
            self.arp_table[src_ip] = src_mac
            self.logger.info(f"Aprendida IP-MAC: {src_ip} -> {src_mac}")

    def block_mac(self, datapath, mac_address):
        """Bloquea una dirección MAC en el switch."""
        if mac_address in self.blocked_macs:
            self.logger.info(f"MAC {mac_address} ya está bloqueada")
            return

        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=mac_address)
        actions = []  # Sin acciones = tráfico bloqueado

        self.add_flow(datapath, 100, match, actions)
        self.blocked_macs.add(mac_address)

        self.logger.info(f"Bloqueada MAC sospechosa: {mac_address}")

    def send_email(self, message):
        """Envía una alerta de ARP Spoofing por correo."""
        self.logger.info("Enviando alerta por correo...")

        correo = "your_email"
        password = "your_password"
        destinatario = "dest_email"

        msg = MIMEMultipart()
        msg['From'] = correo
        msg['To'] = destinatario
        msg['Subject'] = "ALERTA: ARP SPOOFING DETECTADO"
        msg.attach(MIMEText(message, 'plain'))

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(correo, password)
                server.sendmail(correo, destinatario, msg.as_string())
            self.logger.info("Correo de alerta enviado correctamente")
        except Exception as e:
            self.logger.error(f"Error al enviar correo: {e}")
