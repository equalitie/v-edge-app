$(document).ready(function() {

    $("#domain_name").focusout(function(){
        check_domain($(this)[0].value, ".domain_name_ok", ".domain_name_x", ".domain_name_error", "inline");
    });

    $(".new_website_input").focusout(function(){
        check_domain($(this)[0].value, ".domain_name_ok-add", ".domain_name_x-add", ".domain_name_error-add", "block");
    });

    $('#pgp_checkbox').change(function() {
        $(".form_group_pgp_key").toggle();
    });

    $('#ssl_checkbox').change(function() {
        if($("#ssl_checkbox").prop('checked')){
            $(".ssl_files").show()
        }else{
            $(".ssl_files").hide()
        }
    });

    $('.language_chooser').change(function() {
        window.location='/lang/'+this.value
    });

    $('.delete_user').click(function(){
        var user_id = $(this).attr('data-button');
        window.location='users/delete/'+user_id
    })

    $(".purge_website_cache_bt").click(function(){
        purge_cache('.purge_confirm_ok', '.purge_confirm_x');
    });

    $('.help_with_ns').click(function(){
        window.open("/dashboard/support");
    })

    $('.skip_admin_security').click(function(){
        window.location='2.1'
    })

    $('.confirm_ns_moved').click(function(){
        window.location='4.5'
    })

    $('.all_done').click(function(){
        window.location='6'
    })

    // confirm delete website simple
    $('.confirm_delete_simple').click(function(){
        var a = confirm("Are you sure you want to delete this website?")
        if(a){
            window.location='/dashboard/'+site_id+'/setup/delete'
        }
    })

    // DNS zone file records editing
    if($("#record_type").val() == "MX"){
        if($("#record_type").val() == "MX"){
            $(".priority_field").show();
        }
        $(".new_dns_record_name").val(domain_name);
    }

    if($("#record_type").val() == "SRV"){
        if($("#record_type").val() == "SRV"){
            $(".priority_field").show();
            $(".weight_field").show();
        }
    }

    // show dns rescan warning box
    $('.rescan_records').on("click", function() {
        $(".rescan_warning_box").slideToggle();
    });

    // show warning delete website box
    $('.btn-danger').on("click", function() {
        $(".delete_warning_box").slideToggle();
    });

    // change a DNS zone file type
    $("#record_type").change(function () {
        $(".new_dns_record_name").val("");
        $(".new_dns_record_value").val("");

        if($("#record_type").val() == "MX"){
            $(".priority_field").show();
        }else if($("#record_type").val() == "SRV"){
            $(".priority_field").show();
            $(".weight_field").show();
            $(".port_field").show();
        }else{
            $(".priority_field").hide();
            $(".weight_field").hide();
            $(".port_field").hide();
        }
    });

    // delete a DNS zone file record
    $('.delete_bt').click(function(){
        var data = $(this).attr('data-button');
        url = "/dashboard/"+hash_id+"/setup/delete_record?action=delete_record&record_id="+data
        $.ajax({
            type: "GET",
            url: url,
            success: function(e){
                if(e.result){
                    window.location='?deletion_successful=1'
                }else{
                    $(".record_edit_error").show()
                    $(".bg-success").hide()
                    $(".record_edit_error").html(e.error)
                }
            },
            failure: function(e){
                $(".record_edit_error").show()
                $(".bg-success").hide()
                $(".record_edit_error").html("There was an error")
            },
            error: function (e){
                $(".record_edit_error").show()
                $(".bg-success").hide()
                $(".record_edit_error").html("There was an error")
            }
        })
    });

    // purge cache
    var purge_cache = function(class_ok, class_error){
        $(class_error).hide();
        $(class_ok).hide();

        var show_ok = function(){
            $(class_ok).css('display', 'inline');
            $(class_ok).show();
        }
        var show_error = function(){
            $(class_error).css('display', 'inline');
            $(class_error).show();
        }
        $.ajax({
            type: "GET",
            url: '/purge_cache',
            success: function(e){
                show_ok();
            },
            failure: function(e){
                show_error()
            },
            error: function (e){
                show_error()
            }
        })
    }

    // check a domain for validity
    var check_domain = function(url, class_ok, class_error, message_el, d_type){
        $(class_error).hide();
        $(class_ok).hide();
        $(message_el).hide();

        var show_ok = function(){
            $(class_ok).fadeIn();
        }
        var show_error = function(e){
            $(class_error).fadeIn();
            $(message_el).html(e.message);
            $(message_el).css('display', d_type);
        }
        $.ajax({
            type: "GET",
            url: '/check_url?url='+url,
            success: function(e){
                if(e.result){
                    show_ok(e);
                }else{
                    show_error(e);
                }
            }
        })
    }

});