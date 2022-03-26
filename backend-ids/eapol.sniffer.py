def eapol_sniffer_replay(self, pkt):
		fNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
		fMIC = "00000000000000000000000000000000"

		if pkt.haslayer(EAPOL):
			__sn = pkt[Dot11].addr2
			__rc = pkt[Dot11].addr1
			to_DS = pkt.getlayer(Dot11).FCfield & 0x1 !=0
			from_DS = pkt.getlayer(Dot11).FCfield & 0x2 !=0

			if __sn == self.bssid:
				tgt = __rc
			elif __rc == self.bssid:
				tgt = __sn
			else:
				return

			if from_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __sn == self.bssid and nonce != fNONCE and mic == fMIC:
					self.__c_HANDSHAKE[0] = pkt
				elif __sn == self.bssid and nonce != fNONCE and mic != fMIC:
					self.__c_HANDSHAKE[2] = pkt
			elif to_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __rc == self.bssid and nonce != fNONCE and mic != fMIC:
					self.__c_HANDSHAKE[1] = pkt
				elif __rc == self.bssid and nonce == fNONCE and mic != fMIC:
					self.__c_HANDSHAKE[3] = pkt
		return
