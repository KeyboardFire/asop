window.addEventListener('load', function() {

    var maininput = document.getElementsByTagName('input')[0];
    var inputbtns = document.getElementsByClassName('inputbtn');
    for (var i = 0; i < inputbtns.length; ++i) {
        (function(inputbtn) {
            inputbtn.addEventListener('click', function(e) {
                e.preventDefault();
                maininput.value += inputbtn.textContent;
                maininput.focus();
            });
        })(inputbtns[i]);
    }

});
