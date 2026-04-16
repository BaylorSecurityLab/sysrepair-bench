package com.example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class GreetController {

    @GetMapping("/greet")
    @ResponseBody
    public String greet(Greeting g) {
        return "hello " + g.getName();
    }
}
