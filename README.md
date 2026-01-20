# Rajiv Gandhi College Rajiv Gandhi Alumini Network (RGCACS)

Welcome to the **Rajiv Gandhi College of Arts, Commerce & Science Rajiv Gandhi Alumini Network**! This comprehensive web application is designed to manage alumni information, events, discussions, job postings, and mentorship opportunities for the RGCACS alumni association. The application provides a modern platform for alumni to stay connected and engage with each other.

## About Rajiv Gandhi College

**Rajiv Gandhi College of Arts, Commerce & Science** is a premier educational institution dedicated to providing quality education and fostering academic excellence. Our alumni network spans across various industries and continues to contribute to society in meaningful ways.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Secure User Authentication** (Login, Registration, Logout)
- **Role-based Access Control** (Admin and Alumni)
- **Complete Post System** with image uploads and user interactions
- **Enhanced Profile Management** with bio, profile pictures, and post history
- **Event Management** - Create, manage, and RSVP to alumni events
- **Discussion Forums** - Engage in category-based discussions
- **Job Board** - Post and browse career opportunities
- **Mentorship Program** - Connect mentors with mentees
- **Global Search** - Find content across all platform features
- **Admin Dashboard** - Comprehensive administrative controls
- **Analytics & Reporting** - Track engagement and generate reports
- **Email Notifications** - Stay updated with alumni activities
- **File Upload System** - Profile pictures and post images
- **Responsive Design** - Bootstrap-powered mobile-friendly interface

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/RGCACS-Alumni-System.git
   cd RGCACS-Alumni-System

2. **Set Up a Virtual Environment:**
    ```cmd
    python -m venv venv
    source venv/bin/activate   # On Windows, use `venv\Scripts\activate`

3. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt

4. **Set Up Environment Variables:**

    ### Create a `.env` file in the root directory of the project and add the following variables:

    ```bash
    SECRET_KEY=your_secret_key
    MONGO_URI=your_mongo_uri
    MAIL_SERVER=your_mail_server
    MAIL_PORT=your_mail_port
    MAIL_USERNAME=your_mail_username
    MAIL_PASSWORD=your_mail_password

5. **Run the Application:**

    ### Run the application in Virtual Environment 

    ```bash
    python app-using-mongodb.py

## Usage

- Admin:

    > - Log in with the admin credentials.
    > - Manage users, events, discussions, job postings, and mentorship opportunities.

- Alumni:

    > - Register and log in to access the dashboard.
    > - View and RSVP to events, participate in discussions, apply for jobs, and find mentorship opportunities.
    > - Edit their profile and upload a profile picture.

## Dependencies

> - Flask==2.1.2
> - Flask-Login==0.5.0
> - Flask-Mail==0.9.1
> - Flask-PyMongo==2.3.0
> - Flask-Uploads==0.2.1
> - pymongo==4.0.1
> - Werkzeug==2.1.2

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes. Make sure to follow the project's coding standards and write clear commit messages.

> 1. Fork the Project
> 2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
> 3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
> 4. Push to the Branch (`git push origin feature/AmazingFeature`)
> 5. Open a Pull Request