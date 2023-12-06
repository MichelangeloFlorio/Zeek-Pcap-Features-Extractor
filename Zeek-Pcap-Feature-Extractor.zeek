@load base/utils/site
@load base/utils/strings
@load base/utils/numbers
@load base/utils/files
@load base/frameworks/tunnels
@load base/protocols/conn/removal-hooks
@load base/protocols/http
@load base/packet-protocols/tcp
@load base/frameworks/packet-filter
@load base/protocols/conn

module Extractor_Feautures;

export {
	## The connection logging stream identifier.
	redef enum Log::ID += { 
        LOG1,
        LOG2,
        LOG3,
        LOG4,
        LOG5,
        LOG6
    };

	## A default logging policy hook for the stream.
	global log_policy1: Log::PolicyHook;

	## The record type which contains column fields of the connection log.
	type Info_: record {
		## This is the time of the first packet.
		ts:           string            &log;
		## A unique identifier of the connection.
		uid:          string          &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:           conn_id         &log;
		## The transport layer protocol of the connection.
		proto:        transport_proto &log;
		## An identification of an application protocol being sent over
		## the connection.
		service:      string          &log &optional;
		## How long the connection lasted.
		duration:     string        &log &optional;
		## The number of payload bytes the originator sent. 
		orig_bytes:   count           &log &optional;
		## The number of payload bytes the responder sent. 
		resp_bytes:   count           &log &optional;
		## Possible *conn_state* values:
		conn_state:   string          &log &optional;
		## If the connection is originated locally, this value will be T.
		## If it was originated remotely it will be F.  
		local_orig:   bool            &log &optional;
		## If the connection is responded to locally, this value will be T.
		## If it was responded to remotely it will be F.
		local_resp:   bool            &log &optional;
		## Indicates the number of bytes missed in content gaps, which
		## is representative of packet loss. 
		missed_bytes: count           &log &default=0;
		## Records the state history of connections as a string of
		## letters.  
		history:      string          &log &optional;
		## Number of packets that the originator sent.
		orig_pkts:     count      &log &optional;
		## Number of IP level bytes that the originator sent (as seen on
		## the wire, taken from the IP total_length header field).
		orig_ip_bytes: count      &log &optional;
		## Number of packets that the responder sent.
		resp_pkts:     count      &log &optional;
		## Number of IP level bytes that the responder sent (as seen on
		## the wire, taken from the IP total_length header field).
		resp_ip_bytes: count      &log &optional;
		## If this connection was over a tunnel, indicate the
		## *uid* values for any encapsulating parent connections
		## used over the lifetime of this inner connection.
		tunnel_parents: set[string] &log &optional;
        ##Source bits per second
        sload:  double  &log    &optional;
        ##Destination bits per second
        dload: double   &log    &optional;
        ##Mean of the flow packet size transmitted by the src
        smeansz:    double   &log    &optional;
        ##Mean of the flow packet size transmitted by the dst
        dmeansz: double   &log    &optional;
        ## Represents the pipelined depth into the connection of this
		## request/response transaction.
		trans_depth:count           &log &default=0;
        ##The content size of the data transferred from the server’s http service
        reb_bdy_len:       count     &log &default=0;
        ##start time
        start_time:           string            &log &optional;
        ##last time
        last_time:           string            &log &optional;
        ## If source (1) equals to destination (3)IP addresses and port numbers (2)(4)
        ## are equal, this variable takes value 1 else 0 
		is_sm_ips_ports:           string         &log &optional;
        ##If the ftp session is accessed by user and password then 1 else 0
        is_ftp_login: count &log &optional;
        ##user ftp 
        user_ftp: string &log &optional; ##&default = "<unknown>"
        ##password ftp if captured
        pwd_ftp: string &log &optional;
        ##No of flows that has a command in ftp session
        ct_ftp_cmd:count &log &optional;
        ##Packets reported dropped by the system.
        pkts_dropped_: count &default = 0 &log &optional;
        ##Source jitter (mSec)
        sjit:	 interval &log &optional;
	    ##Destination jitter (mSec)
        djit:  interval &log &optional;
        ## Source inter-packet arrival time (mSec)
        sinpkt: interval &log &optional;
        ##Destination inter-packet arrival time (mSec)
        dinpkt: interval &log &optional;
	};
    
    type FlowFeatures: record {
        ## The connection's 4-tuple of endpoint addresses/ports.
		id:           conn_id         &log;
		## The transport layer protocol of the connection.
		proto:        transport_proto &log;
    };

    # type Info3: record {
        
    #     ## If source (1) equals to destination (3)IP addresses and port numbers (2)(4)
    #     ## are equal, this variable takes value 1 else 0 
	# 	    is_sm_ips_ports:           string         &log &optional;
		
    # };

     type eachPackets: record {
       
        # dwin:   count   &log &optional;
        stcpb:    count   &log &optional;
        dtcpb:    count   &log &optional;

        ##Time to live (Source to destination time to live and Destination to source time to live)
        ttl: count &log &optional;

        ##Source TCP window advertisement and Destination TCP window advertisement
        win:   count   &log &optional;

        ##Source packets retransmitted (TCP) and Destination packets retransmitted (TCP)

    };

    type each_TCP_Conn: record {
        ##The time between the SYN and the SYN_ACK packets of the TCP
        synack: interval &log &optional;
        ##The time between the SYN_ACK and the ACK packets of the TCP
        ackdat: interval &log &optional;
        ##The sum of ’synack’ and ’ackdat’ of the TCP.
        tcprtt: interval &log &optional;
        ##For each connection the mean interval between two packets (Source - in mSec)
        m_int_s: interval &log &optional;
        ##For each connection the mean interval between two packets (Destination - in mSec)
        m_int_d: interval &log &optional;
    };

    type infoAllC: record {
        ##Number of flows that has method Post in http service
        http_post: count &log &default=0;
        ##Number of flows that has method Get in http service
        http_get: count &log &default=0;

    };

	global log_1: event(rec: Info_);

    global log_2: event(rec: FlowFeatures);

}

redef record connection += {
	conn1: Info_ &optional;
    conn2: FlowFeatures &optional;
};


global eachP: eachPackets;
global each_TCP_C: each_TCP_Conn;

##record info to print in file infoAllConn.log (Features about the entire file pcap)
global allC: infoAllC;

##
global ts_SYN: time;
global ts_SYNACK: time;
global ts_ACK: time;

##info to print m_int_s
global ts_Packet_Prev_S: time;
global tmp_meanInterval_S: interval = 0.0secs;
global contS: count = 0;
global firstP_S: bool = T;

##info to print m_int_d 
global ts_Packet_Prev_D: time;
global tmp_meanInterval_D: interval = 0.0secs;
global contD: count = 0;
global firstP_D: bool = T;

##counter of flows that has a command in ftp session
global counter_ftp_cmd:count = 0;

##counter of packets loss before
global last_stat_pkts_dropped:count = 0;

##
global set_connection: vector of connection;

##
global last_100_connection: vector of connection;

##different service in the last 100 conncetions
global service_last_100_connection: set[string];

##different Destination port in the last 100 conncetions
global port_D_last_100_connection: set[string];

##different Source port in the last 100 conncetions
global port_S_last_100_connection: set[string];

##different states of connection
global different_states: set[string];
global tmp_table: table[string] of count &default=0;

##info to print Source jiiter
global last_packet_timestamp_S: time;
global average_inter_packet_time_S: interval = 0.0secs ;
global packet_count_S: count = 0;
global jitterS: interval = 0.0secs;
global firstP_S_J: bool = T;

##info to print Destination jiiter
global last_packet_timestamp_D: time;
global average_inter_packet_time_D: interval = 0.0secs ;
global packet_count_D: count = 0;
global jitterD: interval = 0.0secs;
global firstP_D_J:  bool = T;


function get_last_100_Conn(s: vector of connection): vector of connection
{
    
    if(|s| >= 100)
    {
        local tmp:count = |s| - 100;
        return s[|s| - 100 : |s|-1];
    }
    else
    {
        print "There aren't 100 connections in the analyzed file.pcap ";
        return s;
    }
        
}

function get_service_last_100_Conn(s: vector of connection): set[string]
{
    local different_services: set[string];
     # check the last 100 connections and detect the different types of service
    for ( i, c in s )
    {
       if(c$conn?$service)
       {
            if(!(c$conn$service in different_services))
                add different_services[c$conn$service];

        } 
    }

    return different_services;
   
        
}

function get_port_D_last_100_Conn(s: vector of connection): set[string]
{
    local different_ports: set[string];
    # check the last 100 connections and detect the different types of service
    for ( i, c in s )
    {
       if(c$conn?$id)
       {
            if(c$conn$id?$resp_p)
            {
                local port_string = fmt("%s", c$conn$id$resp_p);
                if(!(port_string in different_ports))
                add different_ports[port_string];
            }
            

        } 
    }

    return different_ports;
}

function get_port_S_last_100_Conn(s: vector of connection): set[string]
{
    local different_ports: set[string];
    # check the last 100 connections and detect the different types of service
    for ( i, c in s )
    {
       if(c$conn?$id)
       {
            if(c$conn$id?$orig_p)
            {
                local port_string = fmt("%s", c$conn$id$orig_p);
                if(!(port_string in different_ports))
                add different_ports[port_string];
            }
            

        } 
    }

    return different_ports;
}

function print_feature_37(tmp_table: table[string] of count)
{
    # print feature 37;
    print "-----------Feature 37-----------";

    for(i in tmp_table)
    {
        if(tmp_table[i] == 1) print fmt("There is %d connection whose state is '%s' ", tmp_table[i], i);
        else print fmt("There are %d connections whose state is '%s'", tmp_table[i], i);
    }
    print "----------------------------------------";
    print "";
    print "";

}

function print_feature_41(last_100_connection: vector of connection, service_last_100_connection: set[string])
{
    # print feature 41;
    print "-----------Feature 41-----------";

    for(s in service_last_100_connection)
    {
        print fmt("############################### %s ###############################", s);
        local ip_seen: set[string] = set();
        # print ip_seen;
        for (j, c in last_100_connection)
        {
            local cont:count = 0;
            local conn_id_str = fmt("%s", c$conn$id$orig_h);
            if(!(conn_id_str in ip_seen))
            {
                for (k, c1 in last_100_connection)
                {
                    if(c1$conn?$service)
                    {
                        if(c1$conn$id$orig_h == c$conn$id$orig_h && s == c1$conn$service)
                        cont += 1;
                    }
                    
                }
                add ip_seen[conn_id_str];
                if (cont > 0) {
                    if(cont == 1) print fmt("There is %d connection whose service is '%s' and same IP source '%s'", cont, s, c$conn$id$orig_h);
                    else print fmt("There are %d connections whose service is '%s' and same IP source '%s'", cont, s, c$conn$id$orig_h);
                    
                }
            }
            
            
        }
    }
    print "----------------------------------------";
    print "";
    print "";
}

function print_feature_42(last_100_connection: vector of connection, service_last_100_connection: set[string])
{
    # print feature 42;
   
   
    print "-----------Feature 42-----------";

    for(s in service_last_100_connection)
    {
        print fmt("############################### %s ###############################", s);
        local ip_seen: set[string] = set();
        # print ip_seen;
        for (j, c in last_100_connection)
        {
            local cont:count = 0;
            local conn_id_str = fmt("%s", c$conn$id$resp_h);
            if(!(conn_id_str in ip_seen))
            {
                for (k, c1 in last_100_connection)
                {
                    if(c1$conn?$service)
                    {
                        if(c1$conn$id$resp_h == c$conn$id$resp_h && s == c1$conn$service)
                        cont += 1;
                    }
                    
                }
                add ip_seen[conn_id_str];
                if (cont > 0) {
                    if(cont == 1) print fmt("There is %d connection whose service is '%s' and same IP destination '%s'", cont, s, c$conn$id$resp_h);
                    else print fmt("There are %d connections whose service is '%s' and same IP destination '%s'", cont, s, c$conn$id$resp_h);
                }
            }
            
            
        }
    }

    print "----------------------------------------";
    print "";
    print "";
}

function print_feature_43(last_100_connection: vector of connection)
{
    # print feature 43;
   
   
    print "-----------Feature 43-----------";

    local ip_seen: set[string] = set();
    # print ip_seen;
    for (j, c in last_100_connection)
    {
        local cont:count = 0;
        local conn_id_str = fmt("%s", c$conn$id$resp_h);
        if(!(conn_id_str in ip_seen))
        {
            for (k, c1 in last_100_connection)
            {
                
                if(c1$conn$id$resp_h == c$conn$id$resp_h)
                    cont += 1;
                
                    
            }
            add ip_seen[conn_id_str];
            if (cont > 0) {
                if(cont == 1) print fmt("There is %d connection that has the same IP destination '%s'", cont, c$conn$id$resp_h);
                else print fmt("There are %d connections that have the same IP destination '%s'", cont, c$conn$id$resp_h);
            }
        }      
    }
    

    print "----------------------------------------";
    print "";
    print "";
}

function print_feature_44(last_100_connection: vector of connection)
{
    # print feature 44;
   
   
    print "-----------Feature 44-----------";

    local ip_seen: set[string] = set();
    # print ip_seen;
    for (j, c in last_100_connection)
    {
        local cont:count = 0;
        local conn_id_str = fmt("%s", c$conn$id$orig_h);
        if(!(conn_id_str in ip_seen))
        {
            for (k, c1 in last_100_connection)
            {
                
                if(c1$conn$id$orig_h == c$conn$id$orig_h)
                    cont += 1;
                
                    
            }
            add ip_seen[conn_id_str];
            if (cont > 0) {
                if(cont == 1) print fmt("There is %d connection that has the same IP source '%s'", cont, c$conn$id$orig_h);
                else print fmt("There are %d connections that have the same IP source '%s'", cont, c$conn$id$orig_h);
            }
        }      
    }
    

    print "----------------------------------------";
    print "";
    print "";
}

function print_feature_45(last_100_connection: vector of connection, port_D_last_100_connection: set[string])
{
    # print feature 45;
   
   
    print "-----------Feature 45-----------";

    for(p in port_D_last_100_connection)
    {
        print fmt("############################### %s ###############################", p);
        local ip_seen: set[string] = set();
        # print ip_seen;
        for (j, c in last_100_connection)
        {
            local cont:count = 0;
            local conn_id_str = fmt("%s", c$conn$id$orig_h);
            if(!(conn_id_str in ip_seen))
            {
                for (k, c1 in last_100_connection)
                {
                    if(c1$conn?$id)
                    {
                        if(c1$conn$id?$resp_p)
                        {
                            local port_str = fmt("%s", c1$conn$id$resp_p);
                            if(c1$conn$id$orig_h == c$conn$id$orig_h && p == port_str)
                            cont += 1;
                        }
                        
                    }
                    
                }
                add ip_seen[conn_id_str];
                if (cont > 0) {
                    if(cont == 1) print fmt("There is %d connection whose same IP source is '%s' and destination port is '%s'", cont, c$conn$id$orig_h, p);
                    else print fmt("There are %d connections whose same IP source is '%s' and destination port is '%s'", cont, c$conn$id$orig_h, p);
                }
            }
            
            
        }
    }

    print "----------------------------------------";
    print "";
    print "";
}

function print_feature_46(last_100_connection: vector of connection, port_S_last_100_connection: set[string])
{
    # print feature 46;
   
   
    print "-----------Feature 46-----------";

    for(p in port_S_last_100_connection)
    {
        print fmt("############################### %s ###############################", p);
        local ip_seen: set[string] = set();
        # print ip_seen;
        for (j, c in last_100_connection)
        {
            local cont:count = 0;
            local conn_id_str = fmt("%s", c$conn$id$resp_h);
            if(!(conn_id_str in ip_seen))
            {
                for (k, c1 in last_100_connection)
                {
                    if(c1$conn?$id)
                    {
                        if(c1$conn$id?$orig_p)
                        {
                            local port_str = fmt("%s", c1$conn$id$orig_p);
                            if(c1$conn$id$resp_h == c$conn$id$resp_h && p == port_str)
                            cont += 1;
                        }
                        
                    }
                    
                }
                add ip_seen[conn_id_str];
                if (cont > 0) {
                    if(cont == 1) print fmt("There is %d connection whose same IP destination is '%s' and source port is '%s'", cont, c$conn$id$resp_h, p);
                    else print fmt("There are %d connections whose same IP destination is '%s' and source port is '%s'", cont, c$conn$id$resp_h, p);
                }
            }
            
            
        }
    }

    print "----------------------------------------";
    print "";
    print "";
}

function print_feature_47(last_100_connection: vector of connection)
{
    # print feature 47;
   
   
    print "-----------Feature 47-----------";

    local ip_seen: set[string] = set();
    # print ip_seen;
    for (j, c in last_100_connection)
    {
        local cont:count = 0;
        local conn_id_str = fmt("%s", c$conn$id$orig_h);
        if(!(conn_id_str in ip_seen))
        {
            for (k, c1 in last_100_connection)
            {
                
                if(c1$conn$id$orig_h == c$conn$id$orig_h && c1$conn$id$orig_h == c1$conn$id$resp_h)
                    cont += 1;
                
                    
            }
            add ip_seen[conn_id_str];
            if (cont > 0) {
                if(cont == 1) print fmt("There is %d connection that has the same IP source and destination '%s' ", cont, c$conn$id$orig_h);
                else print fmt("There are %d connections that have the same IP source  and destination'%s'", cont, c$conn$id$orig_h);
            }
        }      
    }
    

    print "----------------------------------------";
    print "";
    print "";
}

function print_infoAllC()
{
    print "";
    print "-----------Number of flows that has method Post in http service-----------";
    print fmt("There are '%d' flows that has method Post in http service", allC$http_post);
    print "----------------------------------------";
    print "";
    print "";

    print "-----------Number of flows that has method Get in http service-----------";
    print fmt("There are '%d' flows that has method Get in http service", allC$http_get);
    print "----------------------------------------";
    print "";
    print "";
}
    
event zeek_init() &priority=5
	{
	Log::create_stream(Extractor_Feautures::LOG1, [$columns=Info_, $ev=log_1, $path="fullLog", $policy=log_policy1]);
    Log::create_stream(Extractor_Feautures::LOG2, [$columns=FlowFeatures, $ev=log_2, $path="flowFeatures", $policy=log_policy1]);
    Log::create_stream(Extractor_Feautures::LOG4, [$columns=eachPackets, $path="infoPackets"]);
    Log::create_stream(Extractor_Feautures::LOG5, [$columns=each_TCP_Conn, $path="infoTCPConn"]);
    # Log::create_stream(Extractor_Feautures::LOG3, [$columns=Info3, $ev=log_conn3, $path="additionalFeatures", $policy=log_policy1]);
    # Log::create_stream(Extractor_Feautures::LOG3, [$columns=Info3, $path="additionalFeatures"]);
    # Log::create_stream(Extractor_Feautures::LOG6, [$columns=infoAllC, $path="infoAllConn"]);
	}

event zeek_done() &priority=5
{
    ##we can also print these informations in a log file, but the file.log would have only one line
	# Log::write(Extractor_Feautures::LOG6, allC);
    ##print on terminal the information about Number of flows that has method Post in http service 
    ##and Number of flows that has method Get in http service
    print_infoAllC();

    ##initialize vector of the last 100 connection detected by zeek in the file.pcap
    last_100_connection = get_last_100_Conn(set_connection);

    ##initialize set of different types of service
    service_last_100_connection = get_service_last_100_Conn(last_100_connection);

    ##initialize set of different types of Dest port
    port_D_last_100_connection = get_port_D_last_100_Conn(last_100_connection);

    ##initialize set of different types of Source port
    port_S_last_100_connection = get_port_S_last_100_Conn(last_100_connection);

    # print feature 37
    print_feature_37(tmp_table);

    # print feature 41
    print_feature_41(last_100_connection, service_last_100_connection);

    # print feature 42
    print_feature_42(last_100_connection, service_last_100_connection);

    # print feature 43
    print_feature_43(last_100_connection);

    # print feature 44
    print_feature_44(last_100_connection);

    # print feature 45
    print_feature_45(last_100_connection, port_D_last_100_connection);

    # print feature 46
    print_feature_46(last_100_connection, port_S_last_100_connection);

    # print feature 47
    print_feature_47(last_100_connection);

    ##other possibility
    # for ( i, c in last_100_connection )
    # {
    #     if(c$conn?$service)
    #         print i, c$conn$service, c$conn$id$orig_h;
    # }
        
    
    # for(c in last_100_connection)
    # {
    #     print c;
    # }
       
}


function conn_state1(c: connection, trans: transport_proto): string
{
	local os = c$orig$state;
	local rs = c$resp$state;

	local o_inactive = os == TCP_INACTIVE || os == TCP_PARTIAL;
	local r_inactive = rs == TCP_INACTIVE || rs == TCP_PARTIAL;

	if ( trans == tcp )
		{
		if ( rs == TCP_RESET )
			{
			if ( os == TCP_SYN_SENT || os == TCP_SYN_ACK_SENT ||
			     (os == TCP_RESET &&
			      c$orig$size == 0 && c$resp$size == 0) )
				return "REJ";
			else if ( o_inactive )
				return "RSTRH";
			else
				return "RSTR";
			}
		else if ( os == TCP_RESET )
			{
			if ( r_inactive )
				{
				if ( /\^?S[^HAFGIQ]*R.*/ == c$history )
					return "RSTOS0";

				return "OTH";
				}

			return "RSTO";
			}
		else if ( rs == TCP_CLOSED && os == TCP_CLOSED )
			return "SF";
		else if ( os == TCP_CLOSED )
			return r_inactive ? "SH" : "S2";
		else if ( rs == TCP_CLOSED )
			return o_inactive ? "SHR" : "S3";
		else if ( os == TCP_SYN_SENT && rs == TCP_INACTIVE )
			return "S0";
		else if ( os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED )
			return "S1";
		else
			return "OTH";
		}

	else if ( trans == udp )
		{
		if ( os == UDP_ACTIVE )
			return rs == UDP_ACTIVE ? "SF" : "S0";
		else
			return rs == UDP_ACTIVE ? "SHR" : "OTH";
		}

	else
		return "OTH";
}

## Fill out the c$conn record for logging
function set_conn1(c: connection, eoc: bool)
{
        
	if ( ! c?$conn1 )
		{
		local p = get_port_transport_proto(c$id$resp_p);
		c$conn1 = Info_($ts=strftime("%Y-%m-%d %H:%M:%S", c$start_time), $uid=c$uid, $proto=p);
        # print fmt("conversion: %s", strftime("%Y-%m-%d %H:%M:%S", c$start_time));
		}
    
	c$conn1$id=c$id;
    # print c$conn1$id;
	if ( c?$tunnel && |c$tunnel| > 0 )
		{
		if ( ! c$conn1?$tunnel_parents )
			c$conn1$tunnel_parents = set();
		add c$conn1$tunnel_parents[c$tunnel[|c$tunnel|-1]$uid];
		}
	if( |Site::local_nets| > 0 )
		{
		c$conn1$local_orig=Site::is_local_addr(c$id$orig_h);
		c$conn1$local_resp=Site::is_local_addr(c$id$resp_h);
		}

	if ( eoc )
	{
		if ( c$duration > 0secs )
			{
			c$conn1$duration=duration_to_mins_secs(c$duration);
			c$conn1$orig_bytes=c$orig$size;
			c$conn1$resp_bytes=c$resp$size;
            # local bps = (count_to_double(c$orig$size) * 8) / c$duration;
            local s_bps = (c$orig$size * 8) / interval_to_double(c$duration);
            local d_bps = (c$resp$size * 8) / interval_to_double(c$duration); ## *8 to convert bytes into bits
            ##DEBUG 
            # print fmt("bits per second source: %f", s_bps);
            # print fmt("bits per second source: %f", d_bps);
            c$conn1$sload = s_bps;
            c$conn1$dload = d_bps;
			}
		if ( c$orig?$num_pkts )
			{
			# these are set if use_conn_size_analyzer=T
			# we can have counts in here even without duration>0
			c$conn1$orig_pkts = c$orig$num_pkts;
			c$conn1$orig_ip_bytes = c$orig$num_bytes_ip;
			c$conn1$resp_pkts = c$resp$num_pkts;
			c$conn1$resp_ip_bytes = c$resp$num_bytes_ip;
			}

		if ( |c$service| > 0 )
			c$conn1$service=to_lower(join_string_set(c$service, ","));

		c$conn1$conn_state=conn_state1(c, get_port_transport_proto(c$id$resp_p));

        ##count number of connession for each different type of state
        if(!(c$conn1$conn_state in different_states))
        {
            add different_states[c$conn1$conn_state];
            tmp_table[c$conn1$conn_state] += 1 ;
        }
        else
        {
            tmp_table[c$conn1$conn_state] += 1 ;
        }
            

		if ( c$history != "" )
			c$conn1$history=c$history;

        if(c$orig?$num_pkts)
        {
            if(c$conn1$orig_pkts > 0 && c$duration > 0secs )
            {
                c$conn1$smeansz = c$conn1$orig_bytes / c$conn1$orig_pkts;
            }
            
            if(c$conn1$resp_pkts > 0 && c$duration > 0secs )
            {
                c$conn1$dmeansz = c$conn1$resp_bytes / c$conn1$resp_pkts;
            }
        }
        

        c$conn1$start_time = strftime("%Y-%m-%d %H:%M:%S", c$start_time);
        
        c$conn1$last_time = strftime("%Y-%m-%d %H:%M:%S", c$start_time + c$duration);

        local ns = get_net_stats();

        # print ns;

	    local new_dropped = ns$pkts_dropped - last_stat_pkts_dropped;

        c$conn1$pkts_dropped_ = new_dropped;

        last_stat_pkts_dropped = new_dropped;

	}

        

}


function set_conn2(c: connection, eoc: bool)
{
	if ( ! c?$conn2 )
		{
		local p = get_port_transport_proto(c$id$resp_p);
		c$conn2 = FlowFeatures($proto=p);
        # print fmt("conversion: %s", strftime("%Y-%m-%d %H:%M:%S", c$start_time));
		}
        c$conn2$id=c$id;
}
    
function set_3(c: connection, eoc: bool)
{
        local ip_s = c$id$orig_h;
        local port_s = c$id$orig_p;
        local ip_d = c$id$resp_h;
        local port_d = c$id$resp_p;
        if(c?$conn1)
        {
            if(ip_s == ip_d && port_s == port_d)
                c$conn1$is_sm_ips_ports= "1";
            else
                c$conn1$is_sm_ips_ports= "0";
        }   
}

event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
	{
	set_conn1(c, F);

	c$conn1$missed_bytes = c$conn1$missed_bytes + length;
	}

event tunnel_changed(c: connection, e: EncapsulatingConnVector) &priority=5
	{
	set_conn1(c, F);
	if ( |e| > 0 )
		{
		if ( ! c$conn1?$tunnel_parents )
			c$conn1$tunnel_parents = set();
		add c$conn1$tunnel_parents[e[|e|-1]$uid];
		}
	c$tunnel = e;
	}

event connection_state_remove(c: connection) &priority=5
	{

    
	set_conn1(c, T);
    set_conn2(c, T);
    set_3(c, T);
    # local orig_window = c$tcp$orig$win_size;
    # local resp_window = c$tcp$resp$win_size;
    # print "orig_window" orig_window;
    # print "resp_window" resp_window;
    # print "get_orig_seq ", get_orig_seq(c$id);
    # print "get_resp_seq ", get_orig_seq(c$id);

    ##add the connection in temp set of connection
    set_connection += c;

   

	}

event connection_state_remove(c: connection) &priority=-5
{
    if(c?$conn1 && c?$ftp)
        c$conn1$ct_ftp_cmd = counter_ftp_cmd;
	Log::write(Extractor_Feautures::LOG1, c$conn1);
    Log::write(Extractor_Feautures::LOG2, c$conn2);
    # Log::write(Extractor_Feautures::LOG3, conn3);

    ##initialize to 0 the counter of flows ftp with command for the next ftp connection
    if(c?$conn1 && c?$ftp)
        counter_ftp_cmd = 0;
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
    
    if(is_orig)
    {
        ##DEBUG
        # print "Source TCP sequence number", seq;
        if(firstP_S)
        {
            ts_Packet_Prev_S = network_time();
            firstP_S = F;
            contS += 1;
        }
        else
        {
            tmp_meanInterval_S = tmp_meanInterval_S + (network_time() - ts_Packet_Prev_S);
            contS += 1;
            ts_Packet_Prev_S = network_time();
        }

        eachP$stcpb = seq;

    }   
    else
    {
        ##DEBUG
        #  print "Destination TCP sequence number", seq;
        if(firstP_D)
        {
            ts_Packet_Prev_D = network_time();
            firstP_D = F;
            contD += 1;
        }
        else
        {
            tmp_meanInterval_D = tmp_meanInterval_D + (network_time() - ts_Packet_Prev_D);
            contD += 1;
            ts_Packet_Prev_D = network_time();
        }

         eachP$dtcpb = seq;
    }

    ##if this log::write is here (in this event), print out only the information of TCP packets
    #Log::write(Extractor_Feautures::LOG4, eachP);
    
}

event new_connection(c: connection) 
{
    if ( ! c?$conn1 )
		{
            local p = get_port_transport_proto(c$id$resp_p);
		    c$conn1 = Info_($ts=strftime("%Y-%m-%d %H:%M:%S", c$start_time), $uid=c$uid, $proto=p);
		}
}

# function set_trans_depth(c: connection)
# {
# 	c$conn1$trans_depth += 1;
# }


# event http_request(c: connection, method: string, original_URI: string,
#                    unescaped_URI: string, version: string) &priority=4
# {
#     # print "fuori http request";
#     if(c?$conn1)
#     {
#         # print "dentro http request";
#         ##set trans_depth
#         #increment of 1 the trans_depth
#         set_trans_depth(c);
#     }
    
# }
# event http_reply(c: connection, version: string, code: count, reason: string) &priority=4
# {
#     # print "fuori http reply";
#     if(c?$conn1 )
#     {
#         # print "dentro http reply";
#         ##set trans_depth
#         #increment of 1 the trans_depth
#         set_trans_depth(c);
#     }
# }

# event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=4
# {
#     # print "fuori http header";
#      if(c?$conn1 )
#     {
#         # print "dentro http header";
#         ##set trans_depth
#         #increment of 1 the trans_depth
#         set_trans_depth(c);
#     }
# }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=4
{
    
    if(c?$conn1 )
    {
        ##set trans_depth
        c$conn1$trans_depth = c$http$trans_depth;
        ##set body_len server
        c$conn1$reb_bdy_len = c$http$response_body_len;
    }
}

event connection_SYN_packet(c: connection, pkt: SYN_packet)
{
    ##print strftime("%Y-%m-%d %H:%M:%S", network_time());
    ts_SYN = network_time();
}

event connection_established(c: connection) 
{
    ts_SYNACK = network_time();
}

event connection_first_ACK(c: connection)
{
    ts_ACK = network_time();
}

event connection_finished(c: connection)
{
    
    if(c?$conn1 && c$conn1$proto == tcp)
    {
        each_TCP_C$synack = ts_SYNACK - ts_SYN;
        each_TCP_C$ackdat = ts_ACK - ts_SYNACK;
        each_TCP_C$tcprtt = each_TCP_C$synack +  each_TCP_C$ackdat;
        if(contS > 0)
            each_TCP_C$m_int_s = tmp_meanInterval_S / contS;
        each_TCP_C$m_int_s = each_TCP_C$m_int_s / 1000;
        if(contD > 0)
            each_TCP_C$m_int_d = tmp_meanInterval_D / contD;
        each_TCP_C$m_int_d = each_TCP_C$m_int_d / 1000;

       

        Log::write(Extractor_Feautures::LOG5, each_TCP_C);

        ##initialize for the next connection TCP 
        tmp_meanInterval_S = 0.0secs;
        contS = 0;
        firstP_S = T;

        ##initialize for the next connection TCP 
        tmp_meanInterval_D = 0.0secs;
        contD = 0;
        firstP_D = T;
    }

    ##set source jitter
    if(packet_count_S > 0)
    {
        c$conn1$sjit = jitterS/packet_count_S;
        c$conn1$sinpkt = average_inter_packet_time_S;
    }
        

    ##set destination jitter
    if(packet_count_D > 0)
    {
        c$conn1$djit = jitterD/packet_count_D;
        c$conn1$dinpkt = average_inter_packet_time_D;
    }
        
    
    ##initialize source jitter, packet count, a boolean attribute and the average inter packet time for the next connection
    jitterS = 0.0secs;
    packet_count_S = 0;
    firstP_S_J = T;
    average_inter_packet_time_S = 0.0secs ;
        
    ##initialize destination jitter, packet count, a boolean attribute and the average inter packet time for the next connection
    jitterD = 0.0secs;
    packet_count_D = 0;
    firstP_D_J = T;
    average_inter_packet_time_D = 0.0secs ;
   
}

event new_packet(c: connection, p: pkt_hdr)
{
   
   
    # if(p?$tcp)
    #  print p$tcp;
    
    if(p?$ip && p$ip?$ttl)
        eachP$ttl = p$ip$ttl;
   
   if(p?$tcp && p$tcp?$win)
        eachP$win = p$tcp$win;

    Log::write(Extractor_Feautures::LOG4, eachP);
    delete eachP$ttl;
    delete eachP$stcpb;
    delete eachP$dtcpb;
    delete eachP$win;

}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    if(method == "GET")
        allC$http_get += 1;
    else if(method == "POST")
        allC$http_post += 1;

}

event ftp_request(c: connection, command: string, arg: string)
{
   
    if(c?$conn1)
    {
        if(command == "USER")
        {
            if(c$ftp$user != "<unknown>")
            {
                c$conn1$is_ftp_login = 1;
                c$conn1$user_ftp = c$ftp$user;
            }
            else
                c$conn1$is_ftp_login = 0;

        }
        if(command == "PASS")
        {
            c$conn1$pwd_ftp = c$ftp$password;
            
        }
        if(command != "")
            counter_ftp_cmd +=1;
    }
}



event tcp_rexmit(c: connection, is_orig: bool, seq: count, len: count, data_in_flight: count, window: count)
{
    print "-----------Segments retransmitted (TCP)-----------";
    if(is_orig)
    {
        print fmt("TCP segment retransmission (Source)");
        print fmt("The segment's relative TCP sequence number is '%d'", seq);
        print fmt ("The length of the TCP segment is '%d'", len);
        print fmt("Number of retransmit bytes '%d'", data_in_flight);
        print fmt("Window size '%d'", window);
    }
    else
    {
        print fmt("TCP segment retransmission (Destination)");
        print fmt("The segment's relative TCP sequence number is '%d'", seq);
        print fmt ("The length of the TCP segment is '%d'", len);
        print fmt("Number of retransmit bytes '%d'", data_in_flight);
        print fmt("Window size '%d'", window);
    }
        
    print "----------------------------------------";
    print "";
    print "";
   
}


event new_packet(c: connection, p: pkt_hdr)
{
    if((c?$id && c$id?$orig_h && p?$ip && p$ip?$src))
    {
        if(c$id$orig_h == p$ip$src)
        {
            ## packet send by orig
            if(firstP_S_J)
            {
                last_packet_timestamp_S = network_time();
                firstP_S_J = F;
                packet_count_S += 1;
            }
            else
            {
                local inter_packet_time:interval = (network_time() - last_packet_timestamp_S);
                jitterS = jitterS + inter_packet_time - average_inter_packet_time_S;

                average_inter_packet_time_S = (average_inter_packet_time_S * packet_count_S + inter_packet_time) / (packet_count_S + 1);
                
                # average_inter_packet_time = average_inter_packet_time + (network_time() - last_packet_timestamp);

                # tmp_meanInterval_S_J = tmp_meanInterval_S_J + (network_time() - ts_Packet_Prev_S_J);
                packet_count_S += 1;
                last_packet_timestamp_S = network_time();
            }

        }   
        else
        {
             ## packet send by dest
            if(firstP_D_J)
            {
                last_packet_timestamp_D = network_time();
                firstP_D_J = F;
                packet_count_D += 1;
            }
            else
            {
                local inter_packet_time_1:interval = (network_time() - last_packet_timestamp_D);
                jitterS = jitterS + inter_packet_time_1 - average_inter_packet_time_D;

                average_inter_packet_time_D = (average_inter_packet_time_D * packet_count_D + inter_packet_time_1) / (packet_count_D + 1);
                
                # average_inter_packet_time = average_inter_packet_time + (network_time() - last_packet_timestamp);

                # tmp_meanInterval_S_J = tmp_meanInterval_S_J + (network_time() - ts_Packet_Prev_S_J);
                packet_count_D += 1;
                last_packet_timestamp_D = network_time();
            }
        }
    }
    

}

################################ fuzzers ################################
event new_packet(c: connection, p: pkt_hdr)
{
    # print p$ip$src;
    # if (c?$service_violation && |c$service_violation| != 0 )
    #     print c$service_violation;
    if(p?$ip && p$ip?$hl)
    {
        local payload_size = p$ip$hl;
        #Fuzzing detection rule: Controls the size of the payload
        if (payload_size < 10 || payload_size > 1000)
        {
            print fmt("Possible fuzzing attack detected: %s", c$conn$id$resp_h);
        }
    }
    

    # Other detection rules can be added based on expected behavior
    ##pattern in the data
    # event packet_contents(c: connection, p: packet_contents)
    # {
    #     local payload_data = p$data;

    #     if ("exploit_pattern" in payload_data)
    #     {
    #         print fmt("Suspicious pattern detected by %s", c$id$orig_h);
    #     }
    # }

    ##Protocol Analysis:
    ##Detects anomalous behavior in the specific protocol (for example, attempts to use invalid commands in a protocol).

#     event ftp_command(c: connection, cmd: string)
#     {
#         if (cmd == "SUSPICIOUS_COMMAND")
#         {
#             print fmt("Suspicious command detected by %s", c$id$orig_h);
#         }
#     }
}

################################ end fuzzers ################################

################################ Analysis ################################
global previous_config_hash: string = "";

function get_config_hash(): string
{
    # Compute and return configuration's hash of zeek 
    local config_file = "/usr/local/zeek/etc/zeekctl.cfg";
    return md5_hash(config_file);
}

function check_config_integrity()
{
    local current_config_hash = get_config_hash();

    if (current_config_hash != previous_config_hash)
    {
        print fmt("Modify at configuration of zeek! ATTENTION");
        # Eventually, other actions.
    }

    # Update configuration's hash 
    previous_config_hash = current_config_hash;
}

event zeek_init()
{
    # Verify the initial configuration
    previous_config_hash = get_config_hash();
}

event zeek_done()
{
    # Verify the initial configuration
    check_config_integrity();
}



################################ end Analysis ################################

################################ Backdoors ################################

event connection_state_remove(c: connection)
{   
    ##192.168.1.2 in an example of IP address intern and x.x.x.x an example of estern IP address (suspect)
    if ( c$conn?$id && fmt("%s", c$conn$id$orig_h) == "192.168.1.2" && fmt("%s", c$conn$id$resp_h) == "x.x.x.x")
    {
        print "Possible backdoor attack detected from 192.168.1.2 to x.x.x.x";
    }
}
################################ end Backdoors ################################

################################ DoS ################################

event connection_state_remove(c: connection)
{
    if (c$conn?$resp_pkts && c$conn$resp_pkts > 1000)
    {
        print "Possible DoS attack detected";
    }
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    if (c?$http && c$http$request_body_len > 1000 || c$http$status_code == 500)
    {
        print "Possible DoS attack detected (large content size of the data transferred from the client or status_code: 500)";
    }
}

event new_packet(c: connection, p: pkt_hdr)
{
    if(p?$ip && p$ip?$hl)
    {
        local payload_size = p$ip$hl;
        if (payload_size > 10000)
        {
            print fmt("Possible DoS attack detected: %s", c$conn$id$resp_h);
        }
    }
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    if (code >= 100)
    {
        print "Possible DoS attack detected (numerical response code returned by the server >= 100)";
    }
}

################################ end DoS ################################

################################ Exploit ################################

event http_request (c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    ##it's possible change exploit with other string about vulnerability
    if (original_URI == "/exploit" || unescaped_URI == "/exploit")
    {
        print "Possible Exploit attack detected (suspect URI)";
    }
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    if (code == 200 && c?$http && c$http$uri == "/malware" || c$http$uri == "/exploit")
    {
        print "Possible Exploit attack detected with exploit uri and code: 200";
    }
}

################################ Generic ################################

##To detect this attack can be used other techniques, but in this script is shown only an example

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    if (|original_URI| > 100)
    {
        print "Long and unusual URI of request HTTP detected";
    }
}

################################ end Generic ################################

################################ Reconnaissance ################################

##Analyzes HTTP requests to detect attempts to explore the website structure or obtain information about available resources.
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    if (original_URI == "/admin" || original_URI == "/config" || original_URI == "/phpinfo.php")
    {
        print "HTTP request to sensitive resources detected, possible reconnaissance activity";
    }
}
##
event dns_unknown_reply(c: connection, msg: dns_msg, ans: dns_answer)
{
    print "Possible reconnaissance activity";
    print msg;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (c?$dns && c$dns$qtype_name == "ANY")
    {
        print "DNS query with type ANY detected, possible reconnaissance activity";
    }
}

################################ end Reconnaissance ################################

################################ Shellcode and Worms ################################

##Shellcode
##This example uses a simple regular expression to search for sequences of bytes that might be indicative of shellcode. 
##Customize and adjust the regex based on your needs and the context of your environment.
event packet_contents(c: connection, contents: string)
{
    if (/[\x90-\xFF]{20}/ in contents)
    {
        print "Potential shellcode detected in source connection";
    }
}

##Worms
##This example considers a connection to be a potential worm if the originating machine sent more than 
##twice as many responses as requests, which could indicate fast spreading behavior typical of a worm.
event connection_state_remove(c: connection)
{
   
    if (c?$conn && c$conn$resp_pkts > 10 && c$conn$resp_pkts > c$conn$orig_pkts * 2)
    {
        print "Potential worm behavior detected in connection";
    }
}

################################ end Shellcode and Worms ################################



