-- Drop all tables if they exist (bundle at the top for a clean slate)
DROP TABLE IF EXISTS graduation_list_students;
DROP TABLE IF EXISTS graduation_lists;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS advisor_students;
DROP TABLE IF EXISTS diplomas;
DROP TABLE IF EXISTS transcript_courses;
DROP TABLE IF EXISTS transcripts;
DROP TABLE IF EXISTS courses;
DROP TABLE IF EXISTS units;
DROP TABLE IF EXISTS deaneries;
DROP TABLE IF EXISTS student_affairs;
DROP TABLE IF EXISTS department_secretaries;
DROP TABLE IF EXISTS advisors;
DROP TABLE IF EXISTS students;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS grade_scale;
DROP TABLE IF EXISTS termination_requests;
DROP TABLE IF EXISTS unit_approvals;
DROP TABLE IF EXISTS termination_forms;
DROP TABLE IF EXISTS termination_unit_approvals;

-- Create Users table (base class)
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);

-- Create Grade Scale table
CREATE TABLE grade_scale (
    id INTEGER PRIMARY KEY,
    grade TEXT UNIQUE,
    numeric_value REAL
);

-- Create Students table
CREATE TABLE students (
    id INTEGER PRIMARY KEY,
    student_id TEXT UNIQUE,
    faculty TEXT,
    department TEXT,
    graduation_status TEXT,
    gpa REAL DEFAULT 0.0,
    total_credits INTEGER DEFAULT 0,
    total_ects INTEGER DEFAULT 0,
    FOREIGN KEY (id) REFERENCES users(id)
);

-- Create Advisors table
CREATE TABLE advisors (
    id INTEGER PRIMARY KEY,
    advisor_id TEXT UNIQUE,
    department_id INTEGER,
    department_name TEXT,
    faculty_name TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id) REFERENCES users(id)
);

-- Create Department Secretary table
CREATE TABLE department_secretaries (
    id INTEGER PRIMARY KEY,
    secretariat_id TEXT UNIQUE,
    department_name TEXT,
    FOREIGN KEY (id) REFERENCES users(id)
);

-- Create Student Affairs table
CREATE TABLE student_affairs (
    id INTEGER PRIMARY KEY,
    student_affair_id TEXT UNIQUE,
    FOREIGN KEY (id) REFERENCES users(id)
);

-- Create Deanery table
CREATE TABLE deaneries (
    id INTEGER PRIMARY KEY,
    deanery_id TEXT UNIQUE,
    faculty_name TEXT,
    faculty_id INTEGER,
    FOREIGN KEY (id) REFERENCES users(id)
);

-- Create Course table
CREATE TABLE courses (
    id INTEGER PRIMARY KEY,
    course_code TEXT UNIQUE NOT NULL,
    course_name TEXT,
    credits INTEGER,
    ects REAL,
    instructor TEXT
);

-- Create Transcript table
CREATE TABLE transcripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    course_code TEXT,
    grade TEXT,
    semester INTEGER,
    passed BOOLEAN,
    FOREIGN KEY (student_id) REFERENCES students(id),
    FOREIGN KEY (course_code) REFERENCES courses(course_code),
    FOREIGN KEY (grade) REFERENCES grade_scale(grade)
);

-- Create Transcript-Course relation (many-to-many)
CREATE TABLE transcript_courses (
    transcript_id INTEGER,
    course_id INTEGER,
    grade TEXT,
    PRIMARY KEY (transcript_id, course_id),
    FOREIGN KEY (transcript_id) REFERENCES transcripts(id),
    FOREIGN KEY (course_id) REFERENCES courses(id)
);

-- Create Diploma table
CREATE TABLE diplomas (
    id INTEGER PRIMARY KEY,
    diploma_id TEXT UNIQUE,
    student_id INTEGER,
    student_name TEXT,
    department TEXT,
    faculty TEXT,
    graduation_date DATE,
    final_gpa REAL,
    FOREIGN KEY (student_id) REFERENCES students(id)
);

-- Termination Form
CREATE TABLE termination_forms (
    id INTEGER PRIMARY KEY,
    student_id INTEGER,
    submission_date DATETIME,
    reason TEXT,
    status TEXT DEFAULT 'not_submitted',
    FOREIGN KEY (student_id) REFERENCES students(id)
);

-- Create units table with unique role constraint
CREATE TABLE units (
    id INTEGER PRIMARY KEY,
    role TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    display_name TEXT NOT NULL,
    is_final_approver BOOLEAN DEFAULT 0
);

-- Insert default units using INSERT OR IGNORE to prevent unique constraint violations
INSERT OR IGNORE INTO units (role, title, display_name, is_final_approver) VALUES
    ('library', 'Library', 'Library Office', 0),
    ('alumni', 'Alumni Office', 'Alumni Relations', 0),
    ('sks', 'SKS', 'Health Culture Sports Office', 0),
    ('it', 'IT Department', 'Information Technology', 0),
    ('student_affairs', 'Student Affairs', 'Student Affairs Office', 1);

-- Per-unit approval tracking
CREATE TABLE termination_unit_approvals (
    termination_id INTEGER,
    unit_id INTEGER,
    unit_role TEXT,
    status TEXT DEFAULT 'pending',
    comment TEXT,
    approval_date DATETIME,
    PRIMARY KEY (termination_id, unit_role),
    FOREIGN KEY (termination_id) REFERENCES termination_forms(id),
    FOREIGN KEY (unit_id) REFERENCES units(id)
);

-- Create Advisor-Student relation (many-to-many)
CREATE TABLE advisor_students (
    advisor_id INTEGER,
    student_id INTEGER,
    status TEXT DEFAULT 'active',
    assigned_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (advisor_id, student_id),
    FOREIGN KEY (advisor_id) REFERENCES advisors(id),
    FOREIGN KEY (student_id) REFERENCES students(id)
);

-- Create Notifications table
CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    notification_type TEXT,
    timestamp DATETIME,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);

-- Create Graduation Lists table
CREATE TABLE graduation_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_type TEXT,
    owner_id INTEGER,
    created_date DATETIME,
    updated_date DATETIME,
    academic_year TEXT,
    semester TEXT,
    status TEXT,
    notes TEXT,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Create Students in graduation lists (many-to-many)
CREATE TABLE graduation_list_students (
    list_id INTEGER,
    student_id INTEGER,
    rank INTEGER,
    gpa REAL,
    total_credits INTEGER,
    total_ects INTEGER,
    added_date DATETIME,
    notes TEXT,
    PRIMARY KEY (list_id, student_id),
    FOREIGN KEY (list_id) REFERENCES graduation_lists(id),
    FOREIGN KEY (student_id) REFERENCES students(id)
);

-- Create termination_requests table
CREATE TABLE termination_requests (
    id INTEGER PRIMARY KEY,
    student_id INTEGER,
    request_date DATETIME,
    status TEXT DEFAULT 'pending',
    reason TEXT,
    completion_date DATETIME,
    final_notes TEXT,
    FOREIGN KEY (student_id) REFERENCES students(id)
);

-- Create unit_approvals table
CREATE TABLE unit_approvals (
    id INTEGER PRIMARY KEY,
    termination_request_id INTEGER,
    unit_role TEXT,
    status TEXT DEFAULT 'pending',
    approval_date DATETIME,
    comments TEXT,
    FOREIGN KEY (termination_request_id) REFERENCES termination_requests(id),
    FOREIGN KEY (unit_role) REFERENCES units(role)
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_students_department ON students(department);
CREATE INDEX idx_students_faculty ON students(faculty);
CREATE INDEX idx_students_graduation_status ON students(graduation_status);
CREATE INDEX idx_advisors_department ON advisors(department_name);
CREATE INDEX idx_graduation_lists_type ON graduation_lists(list_type);
CREATE INDEX idx_graduation_lists_status ON graduation_lists(status);
CREATE INDEX idx_notifications_receiver ON notifications(receiver_id);
CREATE INDEX idx_notifications_type ON notifications(notification_type);
CREATE INDEX idx_unit_approvals_request ON unit_approvals(termination_request_id);

-- Insert grade scale values
INSERT INTO grade_scale (grade, numeric_value) VALUES
('AA', 4.0),
('BA', 3.5),
('BB', 3.0),
('CB', 2.5),
('CC', 2.0),
('DC', 1.5),
('DD', 1.0),
('FD', 0.5),
('FF', 0.0);

-- Insert realistic course data (FIXED: using course_code consistently)
INSERT INTO courses (course_code, course_name, credits, ects, instructor) VALUES
('CENG114', 'Programming I', 1000, 1000, 'Prof. A'),
('CENG115', 'Programming II', 4, 6, 'Prof. A'),
('CENG211', 'Data Structures', 3, 5, 'Prof. B'),
('CENG213', 'Algorithms', 3, 5, 'Prof. B'),
('CENG311', 'Operating Systems', 4, 6, 'Prof. C'),
('CENG313', 'Database Systems', 3, 5, 'Prof. C'),
('CENG411', 'Software Engineering', 4, 6, 'Prof. D'),
('CENG413', 'Computer Networks', 3, 5, 'Prof. D'),
('CENG321', 'Computer Architecture', 3, 5, 'Prof. E'),
('CENG322', 'Compilers', 4, 6, 'Prof. E'),
('CENG323', 'Artificial Intelligence', 3, 5, 'Prof. F'),
('CENG324', 'Machine Learning', 3, 5, 'Prof. F'),
('CENG325', 'Web Programming', 2, 3, 'Prof. G'),
('CENG326', 'Mobile Programming', 2, 3, 'Prof. G'),
('CENG227', 'Object Oriented Programming', 4, 6, 'Prof. H'),
('CENG228', 'Database Management', 3, 5, 'Prof. I'),
('CENG229', 'Software Project', 4, 6, 'Prof. J'),
('CENG230', 'Computer Graphics', 3, 5, 'Prof. K'),
('CENG231', 'Network Security', 3, 5, 'Prof. L'),
('CENG232', 'Mobile App Development', 3, 5, 'Prof. M'),
('CENG233', 'Data Mining', 3, 5, 'Prof. N'),
('CENG234', 'Cloud Computing', 3, 5, 'Prof. O'),
('CENG235', 'IoT Systems', 2, 3, 'Prof. P'),
('CENG236', 'Blockchain Technology', 2, 3, 'Prof. Q'),
('CENG237', 'Calculus I', 4, 6, 'Prof. R'),
('CENG238', 'Calculus II', 4, 6, 'Prof. S'),
('CENG239', 'Physics I', 3, 5, 'Prof. T'),
('CENG240', 'Physics II', 3, 5, 'Prof. U'),
('CENG241', 'Linear Algebra', 3, 5, 'Prof. V'),
('CENG242', 'Statistics', 3, 5, 'Prof. W'),
('CENG243', 'Discrete Mathematics', 3, 5, 'Prof. X'),
('CENG244', 'Digital Logic', 3, 5, 'Prof. Y'),
('CENG245', 'Circuit Analysis', 3, 5, 'Prof. Z'),
('CENG246', 'Electronics', 3, 5, 'Prof. AA'),
('CENG247', 'Signals and Systems', 3, 5, 'Prof. BB'),
('CENG248', 'Engineering Ethics', 2, 3, 'Prof. CC'),
('CENG249', 'Technical Writing', 2, 3, 'Prof. DD'),
('CENG250', 'Internship', 2, 3, 'Prof. EE');

-- Create student status view
CREATE VIEW student_status AS
SELECT 
    s.id as student_id,
    s.student_id as student_number,
    s.faculty,
    s.department,
    s.gpa,
    s.total_credits,
    s.total_ects,
    CASE 
        WHEN s.gpa >= 2.00 AND s.total_credits >= 140 AND s.total_ects >= 240
        THEN 1 
        ELSE 0 
    END AS is_eligible
FROM students s;

-- Create trigger to update student totals when transcript changes
DROP TRIGGER IF EXISTS update_student_totals_on_insert;
CREATE TRIGGER update_student_totals_on_insert
AFTER INSERT ON transcripts
BEGIN
    UPDATE students 
    SET total_credits = (
        SELECT COALESCE(SUM(c.credits), 0)
        FROM transcripts t
        JOIN courses c ON t.course_code = c.course_code
        WHERE t.student_id = NEW.student_id
        AND t.passed = 1
    ),
    total_ects = (
        SELECT COALESCE(SUM(c.ects), 0)
        FROM transcripts t
        JOIN courses c ON t.course_code = c.course_code
        WHERE t.student_id = NEW.student_id
        AND t.passed = 1
    ),
    gpa = (
        SELECT COALESCE(ROUND(AVG(gs.numeric_value), 2), 0.0)
        FROM transcripts t
        JOIN grade_scale gs ON t.grade = gs.grade
        WHERE t.student_id = NEW.student_id
    )
    WHERE id = NEW.student_id;
END;

DROP TRIGGER IF EXISTS update_student_totals_on_update;
CREATE TRIGGER update_student_totals_on_update
AFTER UPDATE ON transcripts
BEGIN
    UPDATE students 
    SET total_credits = (
        SELECT COALESCE(SUM(c.credits), 0)
        FROM transcripts t
        JOIN courses c ON t.course_code = c.course_code
        WHERE t.student_id = NEW.student_id
        AND t.passed = 1
    ),
    total_ects = (
        SELECT COALESCE(SUM(c.ects), 0)
        FROM transcripts t
        JOIN courses c ON t.course_code = c.course_code
        WHERE t.student_id = NEW.student_id
        AND t.passed = 1
    ),
    gpa = (
        SELECT COALESCE(ROUND(AVG(gs.numeric_value), 2), 0.0)
        FROM transcripts t
        JOIN grade_scale gs ON t.grade = gs.grade
        WHERE t.student_id = NEW.student_id
    )
    WHERE id = NEW.student_id;
END;

-- Trigger to update termination status
DROP TRIGGER IF EXISTS update_termination_status;
CREATE TRIGGER update_termination_status
AFTER UPDATE ON unit_approvals
BEGIN
    UPDATE termination_requests 
    SET status = CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM unit_approvals ua
            JOIN units u ON ua.unit_role = u.role
            WHERE ua.termination_request_id = NEW.termination_request_id 
            AND ua.status = 'pending'
            AND u.is_final_approver = 0
        ) THEN 'pending_final_approval'
        WHEN EXISTS (
            SELECT 1 FROM unit_approvals ua
            JOIN units u ON ua.unit_role = u.role
            WHERE ua.termination_request_id = NEW.termination_request_id 
            AND ua.status = 'approved'
            AND u.is_final_approver = 1
        ) THEN 'approved'
        WHEN EXISTS (
            SELECT 1 FROM unit_approvals ua
            WHERE ua.termination_request_id = NEW.termination_request_id 
            AND ua.status = 'rejected'
        ) THEN 'rejected'
        ELSE 'pending'
    END,
    completion_date = CASE
        WHEN EXISTS (
            SELECT 1 FROM unit_approvals ua
            JOIN units u ON ua.unit_role = u.role
            WHERE ua.termination_request_id = NEW.termination_request_id 
            AND ua.status = 'approved'
            AND u.is_final_approver = 1
        ) THEN DATETIME('now')
        ELSE completion_date
    END
    WHERE id = NEW.termination_request_id;
END;

-- Trigger to update graduation_status when student totals change
DROP TRIGGER IF EXISTS update_graduation_status;
CREATE TRIGGER update_graduation_status
AFTER UPDATE OF gpa, total_credits, total_ects ON students
BEGIN
    UPDATE students
    SET graduation_status = 
        CASE
            WHEN gpa >= 2.00 AND total_credits >= 140 AND total_ects >= 240 THEN 'eligible'
            ELSE 'not_eligible'
        END
    WHERE id = NEW.id;
END;

-- Sample users
INSERT INTO users (id, email, password, role) VALUES
(1, 'ali@student.edu', 'hashedpass1', 'student'),
(2, 'ayse@advisor.edu', 'hashedpass2', 'advisor'),
(3, 'fatma@secretary.edu', 'hashedpass3', 'department_secretary'),
(4, 'mehmet@affairs.edu', 'hashedpass4', 'student_affairs'),
(5, 'ahmet@deanery.edu', 'hashedpass5', 'deanery'),
(6, 'zeynep@student.edu', 'hashedpass6', 'student'),
(7, 'kerem@advisor.edu', 'hashedpass7', 'advisor'),
(8, 'leyla@secretary.edu', 'hashedpass8', 'department_secretary'),
(9, 'omer@affairs.edu', 'hashedpass9', 'student_affairs'),
(10, 'sena@deanery.edu', 'hashedpass10', 'deanery'),
(11, 'library@library.edu', 'hashedpass11', 'unit'),
(12, 'alumni@alumni.edu', 'hashedpass12', 'unit'),
(13, 'sks@sks.edu', 'hashedpass13', 'unit'),
(14, 'it@it.edu', 'hashedpass14', 'unit'),
(15, 'affairs@affairs.edu', 'hashedpass15', 'unit');

-- Sample students
INSERT INTO students (id, student_id, faculty, department, graduation_status) VALUES
(1, 'S2023001', 'Engineering', 'Computer Engineering', 'not_eligible'),
(6, 'S2023002', 'Engineering', 'Computer Engineering', 'not_eligible');

-- Sample advisors
INSERT INTO advisors (id, advisor_id, department_id, department_name, faculty_name) VALUES
(2, 'A2023001', 1, 'Computer Engineering', 'Engineering'),
(7, 'A2023002', 1, 'Computer Engineering', 'Engineering');

-- Department secretaries
INSERT INTO department_secretaries (id, secretariat_id, department_name) VALUES
(3, 'SEC2023001', 'Computer Engineering'),
(8, 'SEC2023002', 'Computer Engineering');

-- Student affairs
INSERT INTO student_affairs (id, student_affair_id) VALUES
(4, 'SA2023001'),
(9, 'SA2023002');

-- Deaneries
INSERT INTO deaneries (id, deanery_id, faculty_name, faculty_id) VALUES
(5, 'DEAN2023001', 'Engineering', 1),
(10, 'DEAN2023002', 'Engineering', 1);

-- Advisor-student links
INSERT INTO advisor_students (advisor_id, student_id) VALUES
(2, 1),
(7, 6);

-- Sample transcripts for student 1 (Ali) - enough courses to meet graduation requirements
INSERT INTO transcripts (student_id, course_code, grade, semester, passed) VALUES
(1, 'CENG114', 'AA', 1, 1),
(1, 'CENG115', 'BA', 1, 1),
(1, 'CENG237', 'BB', 1, 1),
(1, 'CENG238', 'CB', 1, 1),
(1, 'CENG211', 'BB', 2, 1),
(1, 'CENG213', 'CB', 2, 1),
(1, 'CENG239', 'CC', 2, 1),
(1, 'CENG240', 'BA', 2, 1),
(1, 'CENG311', 'CC', 3, 1),
(1, 'CENG313', 'BA', 3, 1),
(1, 'CENG241', 'BB', 3, 1),
(1, 'CENG242', 'AA', 3, 1),
(1, 'CENG411', 'BB', 4, 1),
(1, 'CENG413', 'AA', 4, 1),
(1, 'CENG243', 'BA', 4, 1),
(1, 'CENG244', 'BB', 4, 1),
(1, 'CENG321', 'BA', 5, 1),
(1, 'CENG322', 'BB', 5, 1),
(1, 'CENG245', 'CC', 5, 1),
(1, 'CENG246', 'BA', 5, 1),
(1, 'CENG323', 'CC', 6, 1),
(1, 'CENG324', 'BA', 6, 1),
(1, 'CENG247', 'BB', 6, 1),
(1, 'CENG248', 'AA', 6, 1),
(1, 'CENG325', 'AA', 7, 1),
(1, 'CENG326', 'BB', 7, 1),
(1, 'CENG227', 'BA', 7, 1),
(1, 'CENG228', 'BB', 7, 1),
(1, 'CENG229', 'AA', 8, 1),
(1, 'CENG230', 'CB', 8, 1),
(1, 'CENG231', 'CC', 8, 1),
(1, 'CENG232', 'BA', 8, 1),
(1, 'CENG233', 'BB', 8, 1),
(1, 'CENG234', 'AA', 8, 1),
(1, 'CENG235', 'BA', 8, 1),
(1, 'CENG236', 'BB', 8, 1),
(1, 'CENG249', 'AA', 8, 1),
(1, 'CENG250', 'BA', 8, 1);

-- Sample transcripts for student 6 (Zeynep) - enough courses to meet graduation requirements
INSERT INTO transcripts (student_id, course_code, grade, semester, passed) VALUES
(6, 'CENG114', 'BB', 1, 1),
(6, 'CENG115', 'CC', 1, 1),
(6, 'CENG237', 'DC', 1, 1),
(6, 'CENG238', 'CB', 1, 1),
(6, 'CENG211', 'DC', 2, 1),
(6, 'CENG213', 'CB', 2, 1),
(6, 'CENG239', 'CC', 2, 1),
(6, 'CENG240', 'DC', 2, 1),
(6, 'CENG311', 'CC', 3, 1),
(6, 'CENG313', 'DC', 3, 1),
(6, 'CENG241', 'DD', 3, 1),
(6, 'CENG242', 'CC', 3, 1),
(6, 'CENG411', 'DD', 4, 1),
(6, 'CENG413', 'DC', 4, 1),
(6, 'CENG243', 'CC', 4, 1),
(6, 'CENG244', 'CB', 4, 1),
(6, 'CENG321', 'BA', 5, 1),
(6, 'CENG322', 'BB', 5, 1),
(6, 'CENG245', 'CC', 5, 1),
(6, 'CENG246', 'CB', 5, 1),
(6, 'CENG323', 'AA', 6, 1),
(6, 'CENG324', 'BA', 6, 1),
(6, 'CENG247', 'BB', 6, 1),
(6, 'CENG248', 'AA', 6, 1),
(6, 'CENG325', 'BB', 7, 1),
(6, 'CENG326', 'AA', 7, 1),
(6, 'CENG227', 'BA', 7, 1),
(6, 'CENG228', 'BB', 7, 1),
(6, 'CENG229', 'AA', 8, 1),
(6, 'CENG230', 'CB', 8, 1),
(6, 'CENG231', 'CC', 8, 1),
(6, 'CENG232', 'BA', 8, 1),
(6, 'CENG233', 'BB', 8, 1),
(6, 'CENG234', 'AA', 8, 1),
(6, 'CENG235', 'BA', 8, 1),
(6, 'CENG236', 'BB', 8, 1),
(6, 'CENG249', 'AA', 8, 1),
(6, 'CENG250', 'BA', 8, 1);

-- Sample graduation lists
INSERT INTO graduation_lists (id, list_type, owner_id, created_date, updated_date, academic_year, semester, status, notes) VALUES
(1, 'advisor', 2, '2024-05-01', '2024-05-10', '2023-2024', 'spring', 'pending', 'Spring candidates'),
(2, 'department', 3, '2024-05-01', '2024-05-11', '2023-2024', 'spring', 'approved', 'Departmental approval');

-- Students in graduation lists
INSERT INTO graduation_list_students (list_id, student_id, rank, gpa, total_credits, total_ects, added_date) VALUES
(1, 1, 1, 3.15, 144, 252, '2024-05-01'),
(2, 6, 2, 2.11, 142, 246, '2024-05-12');

-- Sample notifications
INSERT INTO notifications (id, sender_id, receiver_id, notification_type, timestamp) VALUES
(1, 2, 1, 'advisor_comment', '2024-05-01 10:00:00'),
(2, 5, 6, 'dean_approval_required', '2024-05-02 14:30:00');

-- Assign all eligible students to Kerem
INSERT INTO advisor_students (advisor_id, student_id, status, assigned_date)
SELECT 
    (SELECT id FROM users WHERE email = 'kerem@iyte.edu.tr'),
    s.id,
    'active',
    '2024-05-25'
FROM students s
WHERE s.graduation_status = 'eligible';

-- Assign all eligible students to Ayse
INSERT INTO advisor_students (advisor_id, student_id, status, assigned_date)
SELECT 
    (SELECT id FROM users WHERE email = 'ayse@iyte.edu.tr'),
    s.id,
    'active',
    '2024-05-25'
FROM students s
WHERE s.graduation_status = 'eligible';



-- Example: Assign eligible students to Kerem and Ayse as advisors

-- Suppose Kerem's email is 'kerem@iyte.edu.tr' and Ayse's email is 'ayse@iyte.edu.tr'
-- Suppose eligible students have emails 'student1@std.iyte.edu.tr', 'student2@std.iyte.edu.tr', etc.

-- Assign 2 eligible students to Kerem
INSERT INTO advisor_students (advisor_id, student_id, status, assigned_date) VALUES
((SELECT id FROM users WHERE email = 'kerem@iyte.edu.tr'), (SELECT id FROM users WHERE email = 'student1@std.iyte.edu.tr'), 'active', '2024-05-25'),
((SELECT id FROM users WHERE email = 'kerem@iyte.edu.tr'), (SELECT id FROM users WHERE email = 'student2@std.iyte.edu.tr'), 'active', '2024-05-25');

-- Assign 2 eligible students to Ayse
INSERT INTO advisor_students (advisor_id, student_id, status, assigned_date) VALUES
((SELECT id FROM users WHERE email = 'ayse@iyte.edu.tr'), (SELECT id FROM users WHERE email = 'student3@std.iyte.edu.tr'), 'active', '2024-05-25'),
((SELECT id FROM users WHERE email = 'ayse@iyte.edu.tr'), (SELECT id FROM users WHERE email = 'student4@std.iyte.edu.tr'), 'active', '2024-05-25');

-- Force graduation_status update for all students after transcript insertions
UPDATE students
SET gpa = gpa;