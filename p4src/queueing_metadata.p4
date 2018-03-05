header_type queueing_metadata_t {
    fields {
        enq_timestamp: 48;

        enq_qdepth: 16;

        deq_timedelta: 32;

        deq_qdepth: 16;

    }
}

metadata queueing_metadata_t queueing_metadata;

