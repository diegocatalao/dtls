#ifndef __H_DTLS_CONATE__
#define __H_DTLS_CONATE__

#define DTLS_CONATE_NO_ERROR        0x1000
#define DTLS_CONATE_INVALID_POINTER DTLS_CONATE_NO_ERROR + 0x01
#define DTLS_CONATE_TIME_ERROR      DTLS_CONATE_NO_ERROR + 0x02

int dtls_conate_timenow(long* obuff);

int dtls_conate_timefmt(long* tms, char* obuff, int size, const char* fmt);

#endif  // __H_DTLS_CONATE__