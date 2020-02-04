package com.example.demo.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
    private static final List<Student> Students = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jons"),
            new Student(3, "Anna Smith"));

    @GetMapping
    public List<Student> getAllStudents() {
        System.out.println("getAllStudents");
        return Students;
    }

    @PostMapping
    public void RegisterNewStudent(@RequestBody Student studentId) {
        System.out.println("RegisterNewStudent");
        System.out.println(studentId);
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable Integer studentId) {
        System.out.println("DeleteStudent");
        System.out.println(studentId);
    }
  @PutMapping(path = "{studentId}")
    public void update(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
      System.out.printf(String.format("%d %s",studentId,student));
    }
}
