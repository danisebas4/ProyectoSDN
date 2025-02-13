import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class HybridMACFloodMitigation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HybridMACFloodMitigation, self).__init__(*args, **kwargs)
        self.mac_count = {}  # Cuenta de nuevas MAC vistas recientemente
        self.blocked_ports = {}  # Puertos bloqueados por actividad sospechosa
        self.flood_threshold = 50  # Umbral de MACs nuevas en 10 segundos
        self.time_window = 10  # Ventana de tiempo en segundos
        self.notification_sent = False  # Para evitar múltiples notificaciones

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Configura el switch para operar en modo híbrido."""
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # 1. Permitir que OVS haga switching automático con OFP_NORMAL
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 0, match, actions)

        # 2. Enviar COPIA de paquetes al controlador para análisis
        match_arp = parser.OFPMatch(eth_type=0x0806)  # ARP
        actions_arp = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, max_len=128),  # Copiar a Ryu
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)  # Permitir switching normal
        ]
        self.add_flow(datapath, 10, match_arp, actions_arp)

        # 3. Enviar COPIA de paquetes Ethernet desconocidos al controlador
        match_eth = parser.OFPMatch(eth_type=0x0800)  # IPv4
        actions_eth = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, max_len=128),  
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        self.add_flow(datapath, 10, match_eth, actions_eth)

        self.logger.info("Switch configurado en modo híbrido.")

    def add_flow(self, datapath, priority, match, actions):
        """Agrega una regla de flujo al switch."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                     match=match, instructions=instructions)
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Maneja paquetes recibidos en el controlador."""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src_mac = eth.src

        # Detectar MAC Flooding
        self.detect_mac_flood(datapath, in_port, src_mac)

    def detect_mac_flood(self, datapath, in_port, src_mac):
        """Detecta MAC Flooding basado en el número de nuevas MAC vistas."""
        current_time = time.time()
        
        # Inicializar contador de MACs por puerto
        if in_port not in self.mac_count:
            self.mac_count[in_port] = []

        # Agregar tiempo actual para esta MAC
        self.mac_count[in_port].append(current_time)

        # Filtrar entradas más antiguas que la ventana de tiempo
        self.mac_count[in_port] = [t for t in self.mac_count[in_port] if current_time - t < self.time_window]

        # Bloquear el puerto si supera el umbral de nuevas MAC
        if len(self.mac_count[in_port]) > self.flood_threshold:
            self.logger.warning(f"MAC Flooding detectado en el puerto {in_port}. Bloqueando el puerto.")

            self.block_port(datapath, in_port)
            
            if not self.notification_sent:
                self.send_email(f"MAC Flooding detectado en el puerto {in_port}. Bloqueando el puerto.")


    def block_port(self, datapath, port):
        """Bloquea un puerto instalando una regla para descartar tráfico."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
    
        # Crear una regla de flujo que coincida con el puerto específico
        match = parser.OFPMatch(in_port=port)
    
        # No especificar acciones, lo que hace que el tráfico se descarte
        actions = []
    
        # Instalar la regla de flujo con una prioridad alta
        self.add_flow(datapath, 100, match, actions)
    
        # Registrar el puerto como bloqueado
        self.blocked_ports[port] = True
        self.logger.info(f"Puerto {port} bloqueado por actividad sospechosa.")
        

    def send_email(self, message):
        """Envía una alerta por correo electrónico."""
        self.logger.info("Enviando notificación por correo...")


        correo = "your_email"
        password = "your_password"
        destinatario = "dest_email"

        mensaje = MIMEMultipart()
        mensaje['From'] = correo
        mensaje['To'] = destinatario
        mensaje['Subject'] = "DETECCIÓN DE ANOMALÍA EN LA RED"
        mensaje.attach(MIMEText(message, 'plain'))

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(correo, password)
                server.sendmail(correo, destinatario, mensaje.as_string())
            self.logger.info("Correo de alerta enviado correctamente.")
        except Exception as e:
            self.logger.error(f"Error al enviar correo: {e}")
	

