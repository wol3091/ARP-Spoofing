package main;

import java.util.ArrayList;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class Main {

	public static void main(String[] args) {
		ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();//�����޼��� ��� ���
		
		int r = Pcap.findAllDevs(allDevs, errbuf);
		if(r == Pcap.NOT_OK || allDevs.isEmpty()) {
			System.out.println("��Ʈ��ũ ��� ã�� �� �����ϴ�." + errbuf.toString());
			return;
		}
		System.out.println("[��Ʈ��ũ ��� Ž�� ����]");
		
		try {
			for (final PcapIf i : allDevs) {
				final byte[] mac = i.getHardwareAddress();
				if(mac == null) {
					continue; 
				}
				System.out.printf("��ġ �ּ�: %s\n���ּ�:%s\n",i.getName(),asString(mac));
			}
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	public static String asString(final byte[] mac) {
		final StringBuilder buf = new StringBuilder();
		for(byte b :mac) {
			if (buf.length() != 0) {
				buf.append(":");
			}
			if(b >= 0 && b < 16) {
				buf.append('0');
			}
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		}
		return buf.toString();
	}

}
