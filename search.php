
<?php

if (isset($_GET['searchinput'])) {
    $search = htmlspecialchars(trim($_GET['searchinput'])); // prevent XSS
    if (strlen($search) < 1) {
        echo "Please enter a search term.";
        exit;
    }

    $conn = new PDO("mysql:host=localhost;dbname=security", "root", "");
    $stmt = $conn->prepare("SELECT * FROM courses WHERE title LIKE :search");
    $stmt->execute(['search' => "%$search%"]);

    $results = $stmt->fetchAll();
    if ($results) {
        foreach ($results as $row) {
            echo "<h1>" . htmlentities($row['title']) . "</h3>";
        }
    } else {
        echo "No results found for \"$search\"";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Responsive Multipage Education Website</title>
    <!-- ICONSCOUT CDN -->
    <link rel="stylesheet" href="https://unicons.iconscout.com/release/v2.1.6/css/unicons.css">

    <!-- GOOGLE FONTS (MONTSERRAT)-->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">

    <!-- STYLESHEETS -->
    <link rel="stylesheet" href="./css/style.css">
    <link rel="stylesheet" href="./css/search.css">

    <style>
      body { background-image: url("./images/bg-texture.png") }
      .courses { margin-top: 1rem  }
    </style>
</head>
<body>
    <nav>
        <div class="container nav__container">
            <a href="index.html" class="nav__logo"><h4>EGATOR</h4></a>
            <ul class="nav__menu">
                <li><a href="index.html">Home</a></li>
                <li><a href="about.html">About</a></li>
                <li><a href="courses.html">Courses</a></li>
                <li><a href="contact.html">Contact</a></li>
            </ul>
            <button id="open-menu-btn"><i class="uil uil-bars"></i></button>
            <button id="close-menu-btn"><i class="uil uil-multiply"></i></button>
        </div>
    </nav>
    <!--====================== END OF NAV =====================-->
    <header>
        <div class="container header__container">
            <div class="header__left">
                <h1>Grow your skills to andvance your career path</h1>
                <p>
                    Lorem ipsum dolor sit amet consectetur adipisicing elit. Quisquam saepe animi, ad quis et atque iste placeat minus ipsa rem?
                </p>
                <a href="courses.html" class="btn btn-primary">Get Started</a>
            </div>
            
            <div class="header__right">
                <div class="header__right-image">
                    <img src="./images/header.svg">
                </div>
            </div>
        </div>
    </header>
    <!--========================== END OF HEADER ============================-->

    
    <section class="faqs">
    <section class="webdesigntuts-workshop">
	<form action="" method="get">		    
		<input type="text" name="searchinput" placeholder="What are you looking for?">		    	
		<button name="Search">Search</button>
	</form>
</section>
    </section>
    
    <footer class="footer">
      <div class="container footer__container">
        <div class="footer__1">
          <a href="index.html" class="footer__logo"><h4>EGATOR</h4></a>
          <p>
            Lorem ipsum dolor sit amet consectetur adipisicing elit. Corporis ipsum nobis ratione.
          </p>
        </div>

        <div class="footer__2">
          <h4>Permalinks</h4>
          <ul class="permalinks">
            <li><a href="index.html">Home</a></li>
            <li><a href="about.html">About</a></li>
            <li><a href="courses.html">Courses</a></li>
            <li><a href="contact.html">Contact</a></li>
          </ul>
        </div>

        <div class="footer__3">
          <h4>Primacy</h4>
          <ul class="privacy">
            <li><a href="#">Privacy Policy</a></li>
            <li><a href="#">Terms and conditions</a></li>
            <li><a href="#">Refund Policy</a></li>
          </ul>
        </div>

        <div class="footer__4">
          <h4>Contact Us</h4>
          <div>
            <p>+01 234 567 8910</p>
            <p>shakir260@gmail.com</p>
          </div>

          <ul class="footer__socials">
            <li>
              <a href="#"><i class="uil uil-facebook-f"></i></a>
            </li>
            <li>
              <a href="#"><i class="uil uil-instagram-alt"></i></a>
            </li>
            <li>
              <a href="#"><i class="uil uil-twitter"></i></a>
            </li>
            <li>
              <a href="#"><i class="uil uil-linkedin-alt"></i></a>
            </li>
          </ul>
        </div>
      </div>

      <div class="footer__copyright">
        <small>Copyright &copy; EGATOR YouTube Tutorials</small>
      </div>
    </footer>
  
  
      <script src="./main.js"></script>
  </body>
  </html>