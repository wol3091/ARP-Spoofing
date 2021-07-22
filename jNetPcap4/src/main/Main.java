package main;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

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
		
		byte[] bytes =new byte[14];
		Arrays.fill(bytes, (byte)0xff);
		ByteBuffer buffer = ByteBuffer.wrap(bytes);
		
		if(pcap.sendPacket(buffer) != Pcap.OK){
			System.out.println(pcap.getErr());
		}
		
		StringBuilder sb = new StringBuilder();
		for(byte b : bytes) {
			sb.append(String.format("%02x", b & 0xff));
		}
		System.out.println("������ ��Ŷ: "+ sb.toString());
		
		pcap.close();
		
	}

}
