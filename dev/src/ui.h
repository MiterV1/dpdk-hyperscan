#ifndef _UI_H_
#define _UI_H_

struct ui_port_filter_s {
    int enabled;
    short src_port;
    short dst_port;
};

struct ui_proto_filter_s {
    int enabled;
    int protocol;
	// 1 - tcp
	// 0 - udp
};

struct ui_app_filter_s {
    int enabled;
    int id;
};

extern int is_ui_port_filter_enabled(void);
extern short get_ui_port_filter_src_port(void);
extern short get_ui_port_filter_dst_port(void);

extern int is_ui_proto_filter_enabled(void);
extern int get_ui_proto_filter_protocol(void);

extern int is_ui_app_filter_enabled(void);
extern int get_ui_app_filter_id(void);

extern void *gtk_ui_main(void *args);

#endif
