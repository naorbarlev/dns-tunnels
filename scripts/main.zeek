# Script for detecting DNS Tunnels attack

@load base/frameworks/notice

module DNS_TUNNELS;

export {
	redef enum Notice::Type += {
		## The volume of the requests is bigger than the threshold.
		RequestCountOverload,

		## The count of numeral of the request is overmuch.
		OvermuchNumber,

		## DNS tunnels attack
		DnsTunnelsAttack
	};

	## The threshold of the request count in a certain period.
	## When the volume of the requests of a specific host is
	## bigger than this threshold, we consider the host is attacked.
	const request_count_threshold = 100 &redef;

	## The legal threshold of the query length
	const query_len_threshold = 27 &redef;

	## The legal percentage of numeral in the query
	const percentage_of_num_count = 0.2 &redef;

	## The expired time of the record
	const record_expiration = 5 min &redef;
}

# Map client ip to query count
# the value that assigned is telling that a record will be removed after 'record_expiration'
global cq_table: table[addr] of count &read_expire=record_expiration;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count,
    qclass: count)
	{
	if ( query == "" )
		return;

	local query_len = |query|;

	local count_of_num = 0;

	local src_ip = c$id$orig_h;

	if ( src_ip in cq_table )
		{
		# checks if the query count for that IP address has exceeded the request_count_threshold
		if ( cq_table[src_ip] + 1 > request_count_threshold )
			{
			NOTICE([ $note=RequestCountOverload, $conn=c, $msg=fmt(
			    "The host %s is overloaded", src_ip) ]);
			delete cq_table[src_ip];
			return;
			}
		else
			{
			#if it is present, the script increments the query count for that IP address
			cq_table[src_ip] += 1;

			# If the length of the query is bgiger than the threshold,
			# we consider this is a suspicious packet and do the DPI.
			local num_string = "0123456789";
			local num_count = 0;
			if ( query_len > query_len_threshold )
				{
				for ( i in query )
					{
					# Calculate numeral count
					if ( i in num_string )
						num_count += 1;
					}
				# The operator "/" will drop the fractional part, so we time 10
				if ( num_count * 10 / query_len > percentage_of_num_count )
					{
					NOTICE([ $note=OvermuchNumber, $conn=c, $msg=fmt(
					    "The numeral in reques is overmuch") ]);
					return;
					}
				}
			}
		}
	else
		{
		#If it is not present, a new entry is added to the cq_table with a query count of 0
		cq_table[src_ip] = 0;
		}
	}
