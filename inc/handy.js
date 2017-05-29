try {
var fa = document.getElementById('btnfaq');
var faq= document.getElementById('faq');
faq.style.display = 'none';
faq.className = 'smalltext';
document.addEventListener('click', function(){ he("faq"); });
fa.addEventListener('click', function(e){ tvee("faq"); location.href='#'; location.href='#btnfaq'; e.preventDefault(); e.stopPropagation(); return false; });
} catch (err) {}

function validateEmail(val) {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(val);
}

function flash(ele, sstart, ssend, duration)
{
	ele.style = sstart;
	setTimeout(duration, endflash(ele,ssend));
}

function endflash(ele,ssend)
{
	ele.style = ssend;
}

function flashClass(elename, cstart, cend, duration)
{
	document.getElementById(elename).className = cstart;
	//ef = "endFlash('"+elename+"','"+cend+"')";
	setTimeout(function(){
			endFlash(elename,cend);
		},duration);
}

function endFlash(elename,cend)
{
	document.getElementById(elename).className = cend;
}

function tvee(elename)
{
	ele = document.getElementById(elename);
	if (ele)
	{
		try 
		{
			if (ele.style.display == 'block' || ele.style.display == '')
			{
			  ele.style.display = 'none';
		   	}
		   	else
		   	{
 			  see(elename);
			}
		}
		catch (err)
		{

		}
	}
}

var eases = new Array();

function he(ele) 
{
   try { document.getElementById(ele).style.display = 'none'; eases[ele] = 0; } catch(err) { }
}

function see(ele) 
{
	// Show element with easing
	try 
	{ 
		obj = document.getElementById(ele);
		if (obj)
		{
			if (obj.style.display != '')
			{
				// Make it transparent
				setOpacity(obj,0);
				// Show it though
				obj.style.display = '';
				eases[ele] = 0;
				setTimeout(function(){seet(ele);},10);
			}
			else
			{
			}
		}
		else
		{

		}
	} 
	catch(err) 
	{
	}
}

function seet(ele)
{
	try
	{
		eases[ele] += 2;
		obj = document.getElementById(ele);
		if (obj)
		{
			setOpacity(obj, eases[ele]);
			if (eases[ele] < 100)
			{
				setTimeout(function(){seet(ele);},10);
			}
		}
		else
		{
		}
	}
	catch (err)
	{
	}
}

function setOpacity(obj, opacity)
{
	obj.style.filter = "alpha(opacity=" + opacity + ")"; // For IE filter to work, obj MUST have layout
	obj.style.KHTMLOpacity = opacity / 100; // Safari and Konqueror
	obj.style.MozOpacity = opacity / 100; // Old Mozilla and Firefox
	obj.style.opacity = opacity / 100; // CSS3 opacity for browsers that support it
}