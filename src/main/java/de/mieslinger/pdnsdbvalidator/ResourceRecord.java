/*
$Id: $
 */
package de.mieslinger.pdnsdbvalidator;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CAARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

/**
 *
 * @author mieslingert
 */
public class ResourceRecord {

    private int rc = 1;
    private String message = "FAILED";
    private Record r = null;
    private String name = null;
    private Long ttl = null;
    private String type = null;
    private Integer prio = null;
    private String content = null;
    private boolean isSOA = false;
    private boolean isNS = false;
    private Resolver resolver = null;

    private ResourceRecord() {
    }

    public ResourceRecord(String nam, Long tt, String typ, Integer priority, String conten, Resolver res) {
        this.name = nam;
        this.ttl = tt;
        this.type = typ;
        this.prio = priority;
        this.content = conten;
        this.resolver = res;

        try {
            switch (type) {
                case "NS":
                    Name ns = new Name(name + ".");

                    // ignore Problems with trailing dots. Newer PDNSes do accept them
                    if (!content.endsWith(".")) {
                        content = content + ".";
                    }

                    Name nsn = new Name(content);
                    r = new NSRecord(ns, DClass.IN, ttl, nsn);
                    message = "OK";
                    rc = 0;
                    isNS = true;
                    break;
                case "CNAME":
                    Name cn = new Name(name + ".");

                    // ignore Problems with trailing dots. Newer PDNSes do accept them
                    if (!content.endsWith(".")) {
                        content = content + ".";
                    }

                    Name ct = new Name(content);
                    r = new CNAMERecord(cn, DClass.IN, ttl, ct);
                    message = "OK";
                    rc = 0;
                    break;
                case "PTR":
                    Name ptr = new Name(name + ".");

                    // ignore Problems with trailing dots. Newer PDNSes do accept them
                    if (!content.endsWith(".")) {
                        content = content + ".";
                    }

                    Name ptrdname = new Name(content);
                    r = new PTRRecord(ptr, DClass.IN, ttl, ptrdname);
                    message = "OK";
                    rc = 0;
                    break;
                case "MX":
                    Name mxn = new Name(name + ".");

                    // ignore Problems with trailing dots. Newer PDNSes do accept them
                    if (!content.endsWith(".")) {
                        content = content + ".";
                    }

                    Name mxt = new Name(content);
                    r = new MXRecord(mxn, DClass.IN, ttl, prio, mxt);
                    message = "OK";
                    rc = 0;
                    break;
                case "SOA":
                    Name soan = new Name(name + ".");
                    String[] soaFields = content.split(" ");

                    if (!soaFields[0].endsWith(".")) {
                        soaFields[0] = soaFields[0] + ".";
                    }
                    Name pri = new Name(soaFields[0]);

                    if (!soaFields[1].endsWith(".")) {
                        soaFields[1] = soaFields[1] + ".";
                    }
                    Name mail = new Name(soaFields[1]);

                    Long serial = Long.parseLong(soaFields[2]);
                    Long refresh = Long.parseLong(soaFields[3]);
                    Long retry = Long.parseLong(soaFields[4]);
                    Long expire = Long.parseLong(soaFields[5]);
                    Long minimum = Long.parseLong(soaFields[6]);
                    r = new SOARecord(soan, DClass.IN, ttl, pri, mail, serial, refresh, retry, expire, minimum);
                    message = "OK";
                    rc = 0;
                    isSOA = true;
                    break;
                case "A":
                    Name an = new Name(name + ".");
                    InetAddress ip4 = InetAddress.getByName(content);
                    r = new ARecord(an, DClass.IN, ttl, ip4);
                    message = "OK";
                    rc = 0;
                    break;
                case "AAAA":
                    Name aaaan = new Name(name + ".");

                    // only jdk9+ know about ipv6 mapped ipv4 addresses
                    // exclude Strings starting with 0:0:0:0:0:ffff:
                    if (!content.startsWith("0:0:0:0:0:ffff:")) {
                        InetAddress ip6 = InetAddress.getByName(content);
                        r = new AAAARecord(aaaan, DClass.IN, ttl, ip6);
                    }
                    message = "OK";
                    rc = 0;
                    break;
                case "SRV":
                    Name srvn = new Name(name + ".");
                    String[] srvFields = content.split(" ");
                    //Integer srvprio = Integer.parseInt(srvFields[0]);
                    Integer weight = Integer.parseInt(srvFields[0]);
                    Integer port = Integer.parseInt(srvFields[1]);

                    // ignore Problems with trailing dots. Newer PDNSes do accept them
                    if (!srvFields[2].endsWith(".")) {
                        srvFields[2] = srvFields[2] + ".";
                    }

                    Name host = new Name(srvFields[2]);
                    r = new SRVRecord(srvn, DClass.IN, ttl, prio, weight, port, host);
                    message = "OK";
                    rc = 0;
                    break;
                case "SPF":
                    Name spfn = new Name(name + ".");
                    r = new SPFRecord(spfn, DClass.IN, ttl, content);
                    message = "OK";
                    rc = 0;
                    break;
                case "TXT":
                    Name txtn = new Name(name + ".");
                    Lookup l = new Lookup(txtn, Type.TXT);
                    l.setResolver(res);
                    Record[] txtCheckRecords = l.run();
                    int rcLookup = l.getResult();
                    if (rcLookup == Lookup.SUCCESSFUL) {

                        if (content.contains("\"")) {
                            List<String> txtStrings = new LinkedList<>();

                            Matcher m = Pattern.compile("\"([^\"]*)\"|(\\S+)").matcher(content);
                            while (m.find()) {
                                if (m.group(1) != null) {
                                    txtStrings.add(m.group(1));
                                } else {
                                    txtStrings.add(m.group(2));
                                }
                                r = new TXTRecord(txtn, DClass.IN, ttl, txtStrings);
                            }
                        } else {
                            if (content.length() > 255) {
                                List<String> txtStrings = new LinkedList<>();
                                int len = content.length();
                                int start = 0;
                                while (len > 0) {

                                    String part = null;
                                    if (len > 255) {
                                        part = content.substring(start, start + 255);
                                    } else {
                                        part = content.substring(start, start + len);
                                    }

                                    txtStrings.add(part);
                                    len = len - 255;
                                    start = start + 255;
                                }
                                r = new TXTRecord(txtn, DClass.IN, ttl, txtStrings);
                            } else {
                                r = new TXTRecord(txtn, DClass.IN, ttl, content);
                            }
                        }

                        message = "OK";
                        rc = 0;
                        break;
                    } else {
                        System.out.println("TXT name: " + name + " content: " + content + " failed");
                        message = "TXT lookup failed";
                        rc = 1;
                        break;
                    }
                case "CAA":
                    Name caan = new Name(name + ".");
                    String[] caaFields = content.split(" ");
                    Integer flags = Integer.parseInt(caaFields[0]);
                    r = new CAARecord(caan, DClass.IN, ttl, flags, caaFields[1], caaFields[2]);
                    message = "OK";
                    rc = 0;
                    break;
                default:
                    message = "Record type not supported";
                    break;
            }
        } catch (Exception e) {
            message = "FAILED: " + e.toString();
        }
    }

    public int getRc() {
        return rc;
    }

    public String getMessage() {
        return message;
    }

    public String getRcMessage() {
        return "" + rc + " " + message;
    }

    public String getName() {
        return name;
    }

    public Long getTtl() {
        return ttl;
    }

    public String getType() {
        return type;
    }

    public Integer getPrio() {
        return prio;
    }

    public String getContent() {
        return content;
    }

    public boolean isSOA() {
        return isSOA;
    }

    public boolean isNS() {
        return isNS;
    }

}
