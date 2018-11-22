/*
 $Id: DomainUpdater.java 5692 2014-11-12 17:23:37Z jjungermann $
 */
package de.mieslinger.pdnsdbvalidator;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

/**
 *
 * @author mieslingert
 */
public class DomainUpdater {

    private ConcurrentLinkedQueue<Long> shortDomainQ;
    private ConcurrentLinkedQueue<String> logFileQ;
    private ConcurrentLinkedQueue<String> criticalLogFileQ;
    final LinkedBlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>();
    private volatile boolean keepOnRunning = true;
    private Thread[] tList = null;

    private DomainUpdater() {
    }

    public DomainUpdater(ConcurrentLinkedQueue<Long> shortDomainQ,
            ConcurrentLinkedQueue<String> logFileQ,
            ConcurrentLinkedQueue<String> criticalLogFileQ,
            int fixedPoolSize) throws Exception {

        this.shortDomainQ = shortDomainQ;
        this.logFileQ = logFileQ;
        this.criticalLogFileQ = criticalLogFileQ;
        this.tList = new Thread[fixedPoolSize];

        for (int i = 0; i < fixedPoolSize; i++) {
            try {
                ShortDomainUpdaterWorker sduw = new ShortDomainUpdaterWorker(shortDomainQ, logFileQ, criticalLogFileQ);
                tList[i] = new Thread(sduw);
                tList[i].setName("worker-" + i);
                tList[i].start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void shutdown() {
        this.keepOnRunning = false;
    }

    private class ShortDomainUpdaterWorker implements Runnable {

        private ConcurrentLinkedQueue<Long> domainIdQ;
        private ConcurrentLinkedQueue<String> logFileQ;
        private ConcurrentLinkedQueue<String> criticalLogFileQ;
        private volatile boolean keepOnRunning = true;
        private Connection cn = null;

        private PreparedStatement getSOARecord = null;
        private PreparedStatement getNameFromDomains = null;
        private PreparedStatement getRecords = null;
        private PreparedStatement insBroken = null;

        // jabber fix
        //private PreparedStatement delJabberRecords = null;
        private SimpleResolver res = null;

        private int updatedDomains = 0;
        private final int batchSize = 1500;

        private ShortDomainUpdaterWorker() {
        }

        public ShortDomainUpdaterWorker(ConcurrentLinkedQueue<Long> DomainIdQ,
                ConcurrentLinkedQueue<String> logFileQ, ConcurrentLinkedQueue<String> criticalLogFileQ) throws Exception {

            this.domainIdQ = DomainIdQ;
            this.logFileQ = logFileQ;
            this.criticalLogFileQ = criticalLogFileQ;

            Class.forName(DataBase.getJdbcClass());
            cn = DriverManager.getConnection(DataBase.getJdbcUrl(), DataBase.getDbUser(), DataBase.getDbPass());
            cn.setAutoCommit(false);

            getNameFromDomains = cn.prepareStatement("select name from domains where id=?");

            getSOARecord = cn.prepareStatement("select name, content from records where domain_id=? and type='SOA'");

            // check only zone apex for broken record
            // to limit effort
            getRecords = cn.prepareStatement("select r.id, r.name, r.ttl, r.type, r.prio, r.content "
                    + "from records r "
                    + "where r.domain_id = ? ");

            //delJabberRecords = cn.prepareStatement("delete from records where domain_id=? and type = 'SRV' and content = ?");
            insBroken = cn.prepareStatement("insert into domainmetadata(domain_id, kind, content) values (?, ?, ?)");

            res = new SimpleResolver();
            res.setAddress(InetAddress.getByName(DataBase.getRecursor()));
            res.setTimeout(2);
        }

        public void run() {
            try {
                while (keepOnRunning) {
                    ResultSet rs = null;
                    String zoneName = null;
                    Long domainId = domainIdQ.poll();
                    if (domainId != null) {
                        updatedDomains++;
                        try {
                            getNameFromDomains.setLong(1, domainId);
                            String domainName = "";
                            ResultSet rsD = getNameFromDomains.executeQuery();
                            if (rsD.first()) {
                                domainName = rsD.getString(1);
                            }
                            rsD.close();
                            logFileQ.add("checking domainId: " + domainId + " domainName: " + domainName);

                            // cleanup old stuff anyway
                            // jabber
                            // das das jemals funktioniert hat. Da hätte NIE ein '.' am Ende sein dürfen.
                            /*
                            delJabberRecords.setLong(1, domainId);
                            delJabberRecords.setString(2, "0 5269 gmx.net.");
                            int i = delJabberRecords.executeUpdate();

                            delJabberRecords.setLong(1, domainId);
                            delJabberRecords.setString(2, "0 5222 gmx.net.");
                            int j = delJabberRecords.executeUpdate();

                            logFileQ.add("Jabber clean complete for " + domainName);
                             */
                            // Check SOA
                            String[] soaStringFields = null;
                            getSOARecord.setLong(1, domainId);
                            rs = getSOARecord.executeQuery();
                            if (rs.next()) {
                                int numSOAs = 0;
                                do {
                                    zoneName = rs.getString(1);
                                    if (!zoneName.equals(domainName)) {
                                        setDomainIdBroken(insBroken, domainId, "SOA name does not match domainstable name");
                                        criticalLogFileQ.add("domain_id: " + domainId + " " + zoneName + " SOA name does not match domainstable name");
                                        break;
                                    }

                                    String soaString = rs.getString(2);
                                    soaStringFields = soaString.split(" ");

                                    if (soaStringFields.length != 7) {
                                        setDomainIdBroken(insBroken, domainId, "SOA invalid");
                                        criticalLogFileQ.add("domain_id: " + domainId + " " + zoneName + " SOA invalid");
                                        break;
                                    }
                                    numSOAs++;
                                } while (rs.next());
                                if (numSOAs > 1) {
                                    setDomainIdBroken(insBroken, domainId, "more than one SOA");
                                    criticalLogFileQ.add("domain_id: " + domainId + " " + zoneName + " more than one SOA");
                                }
                            } else {
                                setDomainIdBroken(insBroken, domainId, "no SOA");
                                criticalLogFileQ.add("domain_id: " + domainId + " " + zoneName + " no SOA");
                            }
                            rs.close();

                            logFileQ.add("SOA checking complete for " + domainName);

                            // Check whether Domain is delegated
                            // assume that if zone is delegated elsewhere it will not have
                            // the SOA exactly like in our DB
                            Lookup l = new Lookup(new Name(zoneName + "."), Type.SOA);
                            l.setResolver(res);
                            Record[] delegationCheckRecords = l.run();
                            int rcLookup = l.getResult();

                            if (rcLookup == Lookup.SUCCESSFUL) {
                                // check if returned SOA matches database SOA
                                // should check whats in
                                // delegationCheckRecords
                                for (Record rec : delegationCheckRecords) {
                                    if (rec.getType() == Type.SOA) {
                                        SOARecord soaRec = (SOARecord) rec;
                                        // compare primary, contact and serial
                                        if (soaStringFields[0].equals(soaRec.getHost().toString(true))
                                                && soaStringFields[1].equals(soaRec.getAdmin().toString(true))
                                                && (Long.parseLong(soaStringFields[2]) == soaRec.getSerial())) {
                                            criticalLogFileQ.add("domain_id: " + domainId + " " + zoneName + " IS delegated to us");

                                            getRecords.setLong(1, domainId);
                                            ResultSet rsZ = getRecords.executeQuery();

                                            while (rsZ.next()) {
                                                ResourceRecord r = new ResourceRecord(rsZ.getString(2), rsZ.getLong(3), rsZ.getString(4), rsZ.getInt(5), rsZ.getString(6), res);
                                                if (r.getRc() != 0) {
                                                    setDomainIdBroken(insBroken, domainId, r.getMessage());
                                                    break;
                                                }
                                            }
                                            rsZ.close();
                                        } else {
                                            criticalLogFileQ.add("domain_id: " + domainId + " " + zoneName + " IS delegated but not to us");
                                        }
                                    }
                                }
                            } else { // rcLookup != Lookup.SUCCESSFUL
                                criticalLogFileQ.add("domain_id: " + domainId + " " + zoneName + " NOT delegated at all");
                            }

                            if (updatedDomains > batchSize) {
                                cn.commit();
                                updatedDomains = 0;
                                logFileQ.add("domain_id: " + domainId + " " + zoneName + " commit send");
                                Thread.sleep(100);
                            }
                        } catch (Exception e) {
                            criticalLogFileQ.add("domain_id: " + domainId + " " + zoneName + " exception: " + e.getMessage());
                            e.printStackTrace();
                        }
                    } else {
                        try {
                            cn.commit();
                            updatedDomains = 0;
                        } catch (Exception e) {
                            criticalLogFileQ.add("domain_id: " + domainId + " commit exception: " + e.getMessage());
                            System.out.println("domain_id: " + domainId + " commit exception: " + e.getMessage());
                            e.printStackTrace();
                        }
                    }
                }
            } catch (Exception e) {
                criticalLogFileQ.add("Strange exception: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    public String join(String r[], String d) {
        if (r.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int i;
        for (i = 0; i < r.length - 1; i++) {
            sb.append(r[i] + d);
        }
        return sb.toString() + r[i];
    }

    private void deleteBullshit(Connection cn, long domainId) {
        try {
            criticalLogFileQ.add("domainId: " + domainId + " delete bogus domain");
            PreparedStatement delDomain = cn.prepareStatement("delete from domains where id=?");
            delDomain.executeUpdate();
            delDomain.close();
        } catch (Exception e) {
        }
    }

    private void setDomainIdBroken(PreparedStatement insBroken, long domainId, String reason) {
        try {
            insBroken.setLong(1, domainId);
            insBroken.setString(2, "broken");
            insBroken.setString(3, reason);
            insBroken.execute();
            System.out.println("domainId: " + domainId + " marked as broken " + reason);
        } catch (Exception e) {
            System.out.println("domainId: " + domainId + " should be marked as broken " + reason);
            e.printStackTrace();
        }
    }

    private void setDomainIdBroken(PreparedStatement insBroken, long domainId) {
        try {
            insBroken.setLong(1, domainId);
            insBroken.setString(2, "broken");
            insBroken.setString(3, "some Reason");
            insBroken.execute();
        } catch (Exception e) {
            System.out.println("domainId: " + domainId + " should be marked as broken");
            e.printStackTrace();
        }
    }

    private void debugDomainId(Connection cn, long domainId, String reason) {
        // dump data of potentially invalid zones/domains
        try {
            StringBuilder sb = new StringBuilder();

            sb.append("domainId: " + domainId + " debug reason: " + reason + "\n");
            PreparedStatement getDomain = cn.prepareStatement("select name from domains where id=?");

            ResultSet rs = null;
            String domainName = null;
            getDomain.setLong(1, domainId);
            rs = getDomain.executeQuery();
            while (rs.next()) {
                domainName = rs.getString(1);
                sb.append(String.format("domains id: %d Name: |%s|\n", domainId, domainName));

            }
            rs.close();
            getDomain.close();

            PreparedStatement getRecords = cn.prepareStatement("select name, type, content from records where domain_id=?");
            getRecords.setLong(1, domainId);
            rs = getRecords.executeQuery();
            while (rs.next()) {
                sb.append(String.format("records domain_id: %d |%s|%s|%s|\n", domainId, rs.getString(1), rs.getString(2), rs.getString(3)));
            }
            rs.close();
            sb.append("-----\n");
            criticalLogFileQ.add(sb.toString());
            getRecords.close();
        } catch (Exception e) {
        }
    }
}
