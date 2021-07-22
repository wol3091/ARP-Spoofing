package main;

import java.util.ArrayList;
import java.util.Date;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

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
		int i = 0;
		for(PcapIf device : allDevs) {
			String description = (device.getDescription() != null) ? 
					device.getDescription() : "��� ���� ������ �����ϴ�.";
			System.out.printf("[%d]��: %s [%s]\n", i++, device.getName(),description);
		}
		
		PcapIf device = allDevs.get(0);
		System.out.printf("������ ��ġ : %s\n",(device.getDescription()!=null)?
				device.getDescription() : device.getName());
		
		int snaplen = 64 * 1024; // ��Ŷ ĸó �뷮
		int flags = Pcap.MODE_PROMISCUOUS; // �ڽ��� ��ǻ�ͷ� ������ ��Ŷ���� �˿����� �޾Ƶ��̴� ���
		int timeout = 1;
		
		Pcap pcap = Pcap.openLive(device.getName(), snaplen,flags,timeout,errbuf);
		if (pcap == null) {
			System.out.printf("��Ŷ ĸó�� ���� ��Ʈ��ũ ��ġ�� ���� ���� �����߽��ϴ�. ���� : "+errbuf.toString());
			return;
		}
				
		
		PcapPacketHandler<String> jPackketHandler = new PcapPacketHandler<String>() {
			@Override
			public void nextPacket(PcapPacket packet, String user) {
				System.out.printf("ĸó �ð�: %s\n��Ŷ�� ����:%-4d",new Date(packet.getCaptureHeader().timestampInMillis()),
						packet.getCaptureHeader().caplen());
			}
		};
		pcap.loop(10, jPackketHandler,"jNetPcap");
		pcap.close();
	}

}
