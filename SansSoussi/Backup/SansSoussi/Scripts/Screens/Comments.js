/// <reference path="../jquery-1.7.1-vsdoc.js" />

function AddComments() {
    if ($("#NewComment:visible").length < 1) {
        $("#NewComment").show();
        $("#NewCommentsBtn").val("Ajouter");
    }
    else {
        $.ajax({
            url: ResolveUrl("~/home/comments"),
            type: "POST",
            data: { comment: $("#NewComment").val() },
            success: function (status) {
                if (status != "success") {
                    alert(status);
                }
                
                $("#NewComment").hide();
                $("#NewCommentsBtn").val("Nouveau commentaire");
            },
            error: function (info) {
                alert(info);
            }
        }
        );
    }
}

function addNewComment() {
    
}