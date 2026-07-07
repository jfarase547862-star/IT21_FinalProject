package com.example.IT21_FinalProject.controller;

import com.example.IT21_FinalProject.DocumentsSigningService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class ResultPageController {

    private final DocumentsSigningService documentsSigningService;

    public ResultPageController(DocumentsSigningService documentsSigningService) {
        this.documentsSigningService = documentsSigningService;
    }

    @GetMapping("/documents/{id}/result-page")
    public String resultPage(@PathVariable("id") String documentId, HttpSession session, Model model) throws Exception {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return "redirect:/login?error=Please+log+in+first.";
        }
        model.addAttribute("result", documentsSigningService.getDocumentResult(documentId));
        return "result";
    }
}
