function zone_file_edit(){
    $(".table_zone_records").hide();
    $(".edit_zone_records").show();
}

function cancel_edit_zone_file(){
    $(".table_zone_records").show();
    $(".edit_zone_records").hide();
}

//
// AJAX to update steps 3 & 5
//

function update_step(website_id, my_class, action, success_c, error_c, loading_c){

    function call_failed(){
        console.log("There was an error sending the email.")
        $(loading_c).hide()
        $(error_c).fadeIn()
        $(my_class).fadeIn()
    }
    var url = "/manage/"+action+"/"+website_id
    $(loading_c).show()
    $(my_class).hide()
    $.ajax({
        type: "GET",
        url: url,
        success: function(e){
            if(e=="1"){
                $(success_c).fadeIn()
                $(loading_c).hide()
                $(my_class).fadeIn()
            }else{
                call_failed()
            }
        },
        failure: function(e){ call_failed(); },
        error: function (e){ call_failed(); }
    })
}


$(document).ready(function() {

    $('.websites_table').DataTable();
    $('.users-table').DataTable();

    // request DNS hosting ticket creation
    $('.create_dns_ticket_request').click(function() {
        var websiteid = $(this).data('websiteid');
        var url = "/redmine/hosting/"+websiteid

        $.ajax({
            type: "POST",
            url: url,
            success: function(data){
                $(".ticket_created_dns").fadeIn();
                $(".create_ticket_p").hide();
            }
        })
    })


    // delete a website
    $('.delete_website_bt').click(function() {
        var a = confirm("This will delete the website. This action cannot be undone. Are you sure?")
        if(a){
            var websiteid = $(this).data('websiteid');
            var url = '/delete_website/'+websiteid

            $.ajax({
                type: "DELETE",
                url: url,
                success: function(e){
                    window.location='/manage'
                }
            })
        }
    })

    // reset step to 0
    $('.admin_reset_setup').click(function() {
        var a = confirm("This will reset the setup to step 0 for this website. Are you sure?")
        if(a){
            var websiteid = $(this).data('websiteid');
            var url = '/setup_reset/'+websiteid

            $.ajax({
                type: "POST",
                url: url,
                success: function(e){
                    window.location=''+websiteid
                }
            })
        }
    })

    //
    // AJAX call to start the scan
    //


    function failed_scan(){
        console.log("scan failed")
        $(".start_scan").show()
        $(".scan_result").html("Could not find NS records for domain.")
        $(".scan_result").show()
        $(".scan_in_progress").hide()
    }

    $('.start_scan').click(function() {
        $(this).hide();
        $(".scan_in_progress").show()
        $(".scan_result").html("")
        $(".confirm_NS_ok").hide()

        var websiteid = $(this).data('websiteid');
        var url = "/scan/"+websiteid

        $.ajax({
            type: "GET",
            url: url,
            success: function(e){
                if(e.data){
                    $(".scan_result").append("<div>Website seems to have the following NS records</div>")
                    $(".scan_result").append("<ul>")
                    $(".start_scan").show()
                    for(i=0;i<e.data.length;i++){
                        $(".scan_result").append("<li>"+e.data[i]+"</li>")
                    }
                    $(".scan_result").append("</ul>")
                    $(".scan_result").append("<br /><p class='bold'>Found "+e.matches.length+" matches with Deflect NS info.</p>")
                    $(".scan_result").show()
                    $(".scan_in_progress").hide()
                    if(e.matches.length > 0){
                        $(".confirm_NS_ok").show()
                    }
                }else{
                    failed_scan()
                }
            },
            failure: function(e){
                failed_scan()
            },
            error: function (e){
                failed_scan()
            }
        })

    });

})