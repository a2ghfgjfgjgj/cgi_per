/*
-----------------------------------------------
Theme: myHosting - Bootstrap Landing Page HTML Template
Version 1.0
Author: EXSYthemes
-----------------------------------------------
// ========== TABLE OF CONTENTS ============ //
	1. Preloader
	2. Slider
    3. SinglePageNav
    4. Mobile Menu
    5. mCustomScrollbar
    6. Mobile menu resize
-----------------------------------------------*/

"use strict";   
/* 1. Preloader */
$(window).on('load', function() { 
	$('.status').fadeOut();
	$('.preloader').delay(350).fadeOut('slow'); 
}); 
/* 1. END Preloader */
(function ($) {   
    var $body = $('body');
    var about = $('.about');
    var showAbout = true;
    var windowHeight = $(window).height();
    var windowWidth = $(window).width();
    $(function () {
		/* 2. Slider */
        $('.intro-slider').slick({
            arrows: true,
            dots: false,
            slide: '.intro-slider__item',
            speed: 1200,
            slidesToShow: 1
        });
        $('.testimonials-slider').slick({
            arrows: false,
            dots: true,
            slide: '.testimonials-slide',
            speed: 1200,
            slidesToShow: 3,
            slidesToScroll: 1,
            responsive: [
                {
                    breakpoint: 1200,
                    settings: {
                        slidesToShow: 2,
                        slidesToScroll: 2
                    }
                },
                {
                    breakpoint: 992,
                        settings: {
                        slidesToShow: 1,
                        slidesToScroll: 1
                    }
                }
            ]
        });
		/* 2. END Slider */
		/* 3. SinglePageNav */
		var navInneer = $(".h-nav");
	    navInneer.singlePageNav({
	        updateHash: false,
	        filter: ":not(.external)",
	        offset: 50,
	        speed: 1000,
	        currentClass: "current",
	        easing: "swing"
	    });
		/* 3. END SinglePageNav */
		/* 4. Mobile Menu */
        $(document).on('click', '.menu-toggle', function(event) {
            event.preventDefault();
            if (!($body.hasClass('js-nav-open')) ) {
                $body.addClass('js-nav-open');
                disableScrolling();
            } else {
                $body.removeClass('js-nav-open');
                enableScrolling();
            }
        });
		/* 4. END Mobile Menu */
		/* 5. mCustomScrollbar */
        $('.advantage__text').mCustomScrollbar({
            theme:"rounded-dots",
            autoHideScrollba: true
        }); // end mCustomScrollbar
        if (windowWidth > 992) {
            $('.service__text').mCustomScrollbar({
                theme:"rounded-dots",
                autoHideScrollba: true
            }); // end mCustomScrollbar
        }
		/* 5. END mCustomScrollbar */
    });
	/* 6. Mobile menu resize */
    $(window).on('resize', function(event) {
        if ($body.hasClass('js-nav-open')) {
            $body.removeClass('js-nav-open');
        }   
        enableScrolling();
    }); // end resize
	/* 6. END Mobile menu resize */
    $(window).on('scroll', function(event) {
        // Animate increment number
        if ( isVisiblePage(about) && showAbout) {
            $('.about__title').spincrement({
                thousandSeparator: '',
                duration: 3000,
            });
            showAbout = false;
        }
    }); // end scroll
    function disableScrolling(){
        var x=window.scrollX;
        var y=window.scrollY;
        window.onscroll=function(){window.scrollTo(x, y);};
    }
    function enableScrolling(){
        window.onscroll=function(){};
    }
    function isVisiblePage(elem) {
        var elemPos = elem.offset().top,
            pagePos = $(window).scrollTop(),
            totalHeight = elemPos + elem.height();

        return ( totalHeight <= pagePos + windowHeight && elemPos >= pagePos);
    }
})(jQuery);