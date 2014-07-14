#define MYPORT "623"
#define MAXBUFLEN 100
#define RMCP_VERSION 0x06
#define ASF_MSG 0x06
#define IPMI_MSG 0x07
#define pong_len 28
#define get_channel_auth_len 30
#define get_session_challenge_len 42
#define activate_session_len 32
#define set_privilege_len 22
#define get_device_id_len 39
#define close_session_len 22
#define get_picmg_len 26
#define PING_CMD -128
#define GET_CHANNEL_AUTH_CMD 0x38
#define GET_SESSION_CHALLENGE_CMD 0x39
#define ACTIVATE_SESSION_CMD 0x3a
#define SET_PRIVILEGE_CMD 0x3b
#define GET_DEVICE_ID_CMD 0x01
#define CLOSE_SESSION_CMD 0x3c
#define GET_PICMG_CMD 0x00


#define IPMI_REQUESTER 0x81
#define IPMI_REQ_LUN_NETFN 0x1C
#define IPMI_CHECKSUM1 0x63
#define IPMI_RESPONDER 0x20
#define PRIVILEGE_USER 0x02

#define AUTH_NONE 0x00
#define AUTH_MD2 0x01
#define AUTH_MD5 0x02
#define SESSION_ID 0x00000000
#define SESSION_ID_TEMP 0x7785610d
#define SUCCESS 0x00
#define DEVICE_ID 0x05
#define DEVICE_REV 0x01
#define DEVICE_NORMAL_OPERATION 0x00
#define DEVICE_FIRMWARE_UPDATE 0x01
#define FIRMWARE_MAJOR 1
#define FIRMWARE_MINOR 0
#define IPMI_VERSION 0x51
#define DEVICE_NONE 0x00
#define MANUFACTURER_ID 0x1bf2 //IPMI forum
#define PRODUCT_ID 0x1234
