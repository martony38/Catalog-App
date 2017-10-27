function resizeImages() {
    // Resize images to keep 2:1 width to heigth ratio.
    $('.img-helper').each(function(index) {
        var imageWidth = $( this ).width();
        $( this ).css({
            'height': imageWidth / 2 + 'px'
        });
    });
};

// Resize images when DOM is ready.
$(resizeImages());

// Resize images each time the window size changes.
$( window ).resize(function() {
    resizeImages();
});

var maxFileSize = $('.form-control-file').data('max-file-size');
var originalImageURL = $('.card-img-top').attr('src');

// Event handler that Check the size and update the image when a new image is uploaded.
$('.form-control-file').change(function() {

    // remove previous error message if present
    $('.alert').remove();

    // If image is too big, remove it from the form and display error message.
    if (this.files[0].size > maxFileSize) {
        this.value = "";
        $('main').prepend('<div class="alert alert-danger" role="alert">File is too large. Please select a file less than ' + (maxFileSize/1024/1024).toString() +' MB</div>');

        // Revoke any previous object URL (for optimal performance and memory usage)
        window.URL.revokeObjectURL($('.card-img-top').attr('src'));

        if (this.id == 'NewItemUploadImage') {
            // Remove entire image element if creating a new item.
            $('.card-img-top').remove();
        }
        else {
            // Restore original image if editing an existing item.
            $('.card-img-top').attr('src',originalImageURL);
        }
    }
    else {

        if (this.id == 'NewItemUploadImage') {
            // Add image element if none is present when creating a new item.
            if (!$('.card-img-top').length) {
                $('form').prepend('<img class="card-img-top" src="" alt="new item image">');
            }
        }

        $('.card-img-top').attr('src', window.URL.createObjectURL(this.files[0]));
        //window.URL.revokeObjectURL($('.card-img-top').attr('src'));
    };
});