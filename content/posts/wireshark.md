---
title: "Writing a Wireshark dissector to parse data embedded in ICMP headers"
date: 2024-06-28T09:06:43-04:00
draft: false
author: hyp
---

# Writing a Wireshark dissector to parse data embedded in ICMP headers

I recently spent some time repurposing fields in ICMP headers in order to do a basic file transfer. I decided to use the code, ID, and sequence fields to achieve this which meant I could fit 5 bytes of data into each header. The PoC implementation was very straightforward to create using scapy. Essentially just read in the file and for every 5 bytes create an ICMP packet, append that packet to a list, and send out the list of packets once complete. The PoC script can be found here: [https://github.com/scratchadams/wireshark/blob/main/icmp.py](https://github.com/scratchadams/wireshark/blob/main/icmp.py)

After creating this PoC, I thought it might be interesting to write a custom Wireshark dissector to parse out the ‘data’ fields and somehow rebuild the data stream so the file’s binary data could be viewed within Wireshark. The first part of this task was actually pretty easy to accomplish, the official Wireshark documentation has some great instructions on how to create a dissector as a C plugin which were very helpful for getting started: [https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html) . The second part of this task proved to be much more difficult than I had initially expected, and I ended up making a number of edits to the Wireshark source code and learning a bit about how protocol dissectors are created in the main source tree (outside of plugins). In this writeup, I am going to break down my dissector, as well as some relevant subsystems within the Wireshark source where I made changes.

The first step in creating any dissector is registering the protocol. The following function: **proto_register_muhproto** was created to register the protocol when Wireshark starts up, as well as initialize some values such as the protocol fields. I won’t go into too many details about this registration process, as it is covered very well in the official documentation, but there is a particular function called during this registration process that I do want to call out. This function is **register_follow_stream** and is called as such:

```
register_follow_stream(proto_muhproto, "muhproto_follow", muhproto_follow_conv_filter, muhproto_follow_index_filter, muhproto_follow_address_filter, udp_port_to_display, follow_tvb_tap_listener);
```

This purpose of this function is to register the protocol and associated filters so that they can be treated as a stream of data within Wireshark. This is going to be a very important part of rebuilding the binary data from our file transfer, as it will allow us to associate the packets hitting our dissector as continuous data. Let’s break down the arguments to this function so we can get a better idea of what is going on here.

The first argument, **proto_muhproto**, is the protocol ID that is returned upon registering the dissector protocol and is used to associate the filters and handlers passed through this function with the protocol defined in our dissector. The second argument, **“muhproto_follow”**, is what is called a ‘tap listener string’ (more on taps later). The third, fourth, and fifth arguments are functions that define filters associated with the protocol being dissected. For example, the **muhproto_follow_index_filter** function is defined as such:

```
static gchar *muhproto_follow_index_filter(guint stream,   
    guint sub_stream _U_)   
{  
      
    return ws_strdup_printf("muhproto.stream eq %u", stream);
}
```

The above filter gets applied when the **FollowStreamDialog** is triggered for this particular protocol, which is exposed through the UI by either clicking ‘**Analyze > Follow > [Protocol Type]’** menu option in the toolbar or right-clicking a packet and selecting ‘**Follow > [Protocol Type]’.** We can see how this is called by looking at the call stack in GDB:

![](/images/1_0qnOynnUhJAiQ8yBs2Bl9A.png)

We will get into the details about how the follow options are added to the UI for our protocol later in the article, but for now it is just important to know that these filters get associated with the protocol follow stream. The next argument passed to the **register_follow_stream** function is **udp_port_to_display**. For the purpose of this dissector, this particular function is just a placeholder and should always return 0, but typically a transport protocol such as TCP or UDP is going to reference port numbers to help differentiate between streams, and the function that is passed here for other such protocols should return the valid port number in use.

The final argument passed to **register_follow_stream** is **follow_tvb_tap_listener,** which is a tap function handler used to provide the follow stream data in tvb format, which is short for ‘Testy Virtual Buffer’ and is described as a buffer designed to throw an exception if an attempt is made to read outside its boundaries. Adding a tap interface to a protocol dissector allows other items within Wireshark to interact with packet data as it is being dissected. We register the tap interface for our dissector with the following call:

```
muh_follow_tap = register_tap("muhproto_follow");
```

Once the tap interface is registered, it can be called from the packet dissect function as such:

```
tap_queue_packet(muh_follow_tap, pinfo, tvb);
```

The above function will push the packet that is being dissected to anything that is currently tapping the protocol. The first argument provides the ID of the registered tap interface, the second argument provides a packet information structure of the packet being dissected, and the third argument provides the packet data buffer from which we will reconstruct our binary.

The source comments for **tap_queue_packet** mention that the “tap reader is responsible to know how to parse any structure pointed to by the tap specific data pointer”. We can see this behavior in action within the **readFollowStream** method which is called when the **openFollowStreamDialog** method is triggered from the UI as seen in this call stack:

![](/images/1_u4bOF2UaCqYeachI94RngA.png)

**readFollowStream** loops through the packets in the follow stream, grabs the data from the packet structure, then appends that data to a buffer which gets passed to **showBuffer** which handles writing that data to the stream dialog display. To properly parse out the binary data from the packets being handled by my dissector, I added an exception within this function to handle any packets of type **MUHPROTO**, and only append specific bytes to the data buffer being passed to **showBuffer** instead of appending the entire packet.

The additions of the tap handler and follow stream to our dissector provide the ability to treat ICMP packets between two hosts as a stream, and the added exception to the follow stream dialog ensures that the data being presented in that stream is only the binary data that we have embedded into certain fields of the ICMP header.

Now that we have the ability to treat the header data as a stream, there is some additional work that needs to be done to expose this functionality for our registered protocol in the UI. Wireshark uses the Qt framework for its GUI and makes use of the designer UI file type that this framework provides. A designer UI file essentially allows UI elements to be defined in XML format which get generated into C++ at compile time. Check out the Qt documentation for some more information on how this works: [https://doc.qt.io/qt-5/designer-using-a-ui-file.html](https://doc.qt.io/qt-5/designer-using-a-ui-file.html)

I was able to determine how to add the proper UI elements for my protocol to the UI by referencing the source code for UDP follow streams. The first thing that needs to be create is a method that will ultimately get referenced in the UI designer file, which is defined as follows:

```
void WiresharkMainWindow::on_actionAnalyzeFollowMUHStream_triggered()  
{  
    openFollowStreamDialogForType(FOLLOW_MUHPROTO);  
}

```
We can see that our method **on_actionAnalyzeFollowMUHStream_triggered** calls the **openFollowStreamDialogForType** method and passes **FOLLOW_MUHPROTO** as an argument. That particular argument needs to be added to an already defined enum located in epan/follow.h as such:

```
/* Type of follow we are doing */  
typedef enum {  
    FOLLOW_TCP,  
    FOLLOW_TLS,  
    FOLLOW_UDP,  
    FOLLOW_DCCP,  
    FOLLOW_HTTP,  
    FOLLOW_HTTP2,  
    FOLLOW_QUIC,  
    FOLLOW_SIP,  
    FOLLOW_MUHPROTO,  
} follow_type_t;

```
The **openFollowStreamDialogForType** method then calls **openFollowStreamDialog** passing along the type, which creates a new **FollowStreamDialog.** Within the **FollowStreamDialog** method, we need to create an additional case within the switch statement that handles our protocol type as such:

```
switch(type)  
    {  
    case FOLLOW_TCP:  
        follower_ = get_follow_by_name("TCP");  
        break;  
    case FOLLOW_TLS:  
        follower_ = get_follow_by_name("TLS");  
        break;  
    case FOLLOW_UDP:  
        follower_ = get_follow_by_name("UDP");  
        break;  
    case FOLLOW_DCCP:  
        follower_ = get_follow_by_name("DCCP");  
        break;  
    case FOLLOW_HTTP:  
        follower_ = get_follow_by_name("HTTP");  
        break;  
    case FOLLOW_HTTP2:  
        follower_ = get_follow_by_name("HTTP2");  
        break;  
    case FOLLOW_QUIC:  
        follower_ = get_follow_by_name("QUIC");  
        break;  
    case FOLLOW_SIP:  
        follower_ = get_follow_by_name("SIP");  
        break;  
    case FOLLOW_MUHPROTO:  
        follower_ = get_follow_by_name("MUHPROTO");  
        break;  
    default :  
        ws_assert_not_reached();  
    }
```

The **get_follow_by_name** function that is triggered by this case does a search through the list of registered followers based on the protocol short name passed as an argument (**MUHPROTO** in this case) and returns a tap interface associated with that protocol. After a new **FollowStreamDialog** is created, the **follow** method is called. I added an additional case to the switch statement for handling protocol types in this method as well, which will update some values in the UI:

```
case FOLLOW_MUHPROTO:  
    {  
        int stream_count = 1;  
        ui->streamNumberSpinBox->blockSignals(true);  
        ui->streamNumberSpinBox->setMaximum(stream_count-1);  
        ui->streamNumberSpinBox->setValue(stream_num);  
        ui->streamNumberSpinBox->blockSignals(false);  
        ui->streamNumberSpinBox->setToolTip(tr("%Ln total stream(s).", "", stream_count));  
        ui->streamNumberLabel->setToolTip(ui->streamNumberSpinBox->toolTip());break;  
    }
```

Ultimately, the **follow** method will call another method called **followStream** which calls **readStream** where another type case will need to be added as follows:
```

switch(follow_type_) {    case FOLLOW_TCP :  
    case FOLLOW_UDP :  
    case FOLLOW_MUHPROTO:  
    case FOLLOW_DCCP :  
    case FOLLOW_HTTP :  
    case FOLLOW_HTTP2:  
    case FOLLOW_QUIC:  
    case FOLLOW_TLS :  
    case FOLLOW_SIP :  
        ret = readFollowStream();  
        break;default :  
        ret = (frs_return_t)0;  
        ws_assert_not_reached();  
        break;  
    }
```

As we can see above, for every protocol that we have a type case defined in this switch statement we will call **readFollowStream** which was the method we mentioned earlier that handles reading and displaying the packet data.

The final portion of adding the follow stream functionality for our protocol will address adding the actual menu options for enabling a follow stream dialog, as well as creating a trigger to enable that menu option when a packet that matches the defined protocol is selected. To achieve this, we need to add an action to the UI designer file for the Wireshark main window (**ui/qt/wireshark_main_window.ui**) like so:

```
<action name="actionAnalyzeFollowMUHStream">  
   <property name="enabled">  
    <bool>false</bool>  
   </property>  
   <property name="text">  
    <string>MUHPROTO Stream</string>  
   </property>  
</action>
```

Then we need to reference the action in the existing Follow menu widget in the same file like so:

```
<widget class="QMenu" name="menuFollow">  
     <property name="title">  
      <string>Follow</string>  
     </property>  
     <addaction name="actionAnalyzeFollowTCPStream"/>  
     <addaction name="actionAnalyzeFollowUDPStream"/>  
     **<addaction name="actionAnalyzeFollowMUHStream"/>**  
     <addaction name="actionAnalyzeFollowDCCPStream"/>  
     <addaction name="actionAnalyzeFollowTLSStream"/>  
     <addaction name="actionAnalyzeFollowHTTPStream"/>  
     <addaction name="actionAnalyzeFollowHTTP2Stream"/>  
     <addaction name="actionAnalyzeFollowQUICStream"/>  
     <addaction name="actionAnalyzeFollowSIPCall"/>  
</widget>
```

We should note that the action has a property named **Enabled** which is set to false by default.

Next we will extend the **proto_get_frame_protocols** function by adding an additional argument and some logic to handle our protocol. This function will set the passed argument to true if the currently selected packet matches our protocol:

```
void  
proto_get_frame_protocols(const wmem_list_t *layers, gboolean *is_ip,  
              gboolean *is_tcp, gboolean *is_udp,  
              gboolean *is_sctp, gboolean *is_tls,  
              gboolean *is_rtp,  
              gboolean *is_lte_rlc,  
              gboolean *is_muhproto)  
{  
    wmem_list_frame_t *protos = wmem_list_head(layers);  
    int     proto_id;  
    const char *proto_name;    while (protos != NULL)  
    {  
        proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));  
        proto_name = proto_get_protocol_filter_name(proto_id);        
        if (is_ip && ((!strcmp(proto_name, "ip")) ||  
                  (!strcmp(proto_name, "ipv6")))) {  
            *is_ip = TRUE;  
        } else if (is_tcp && !strcmp(proto_name, "tcp")) {  
            *is_tcp = TRUE;  
        } else if (is_udp && !strcmp(proto_name, "udp")) {  
            *is_udp = TRUE;  
        } else if (is_sctp && !strcmp(proto_name, "sctp")) {  
            *is_sctp = TRUE;  
        } else if (is_tls && !strcmp(proto_name, "tls")) {  
            *is_tls = TRUE;  
        } else if (is_rtp && !strcmp(proto_name, "rtp")) {  
            *is_rtp = TRUE;  
        } else if (is_lte_rlc && !strcmp(proto_name, "rlc-lte")) {  
            *is_lte_rlc = TRUE;  
        } else if (is_muhproto && !strcmp(proto_name, "muhproto")) {  
            *is_muhproto = TRUE;  
        }
```

Finally, we will add a call to check the argument set by **proto_get_frame_protocols** which if true will enable the menu option and make it clickable:

```
    main_ui_->actionAnalyzeFollowTCPStream->setEnabled(is_tcp);  
    main_ui_->actionAnalyzeFollowUDPStream->setEnabled(is_udp);  
    main_ui_->actionAnalyzeFollowMUHStream->setEnabled(is_muhproto); 
    main_ui_->actionAnalyzeFollowDCCPStream->setEnabled(is_dccp);  
    main_ui_->actionAnalyzeFollowTLSStream->setEnabled(is_tls && !is_quic);  
    main_ui_->actionAnalyzeFollowHTTPStream->setEnabled(is_http);  
    main_ui_->actionAnalyzeFollowHTTP2Stream->setEnabled(is_http2);  
    main_ui_->actionAnalyzeFollowQUICStream->setEnabled(is_quic);  
    main_ui_->actionAnalyzeFollowSIPCall->setEnabled(is_sip);

```
At this point, the protocol dissection and follow stream functionality should be fully functional and can be tested with the python script linked at the top of the article. I have included the source to my dissector in this repo and will be adding some file diffs to cover the portions of the main source tree that were adjusted to add this functionality:

[https://github.com/scratchadams/wireshark](https://github.com/scratchadams/wireshark)

![](/images/1_dWbdVtzaJ-ld-f0VKzQOow.png)

