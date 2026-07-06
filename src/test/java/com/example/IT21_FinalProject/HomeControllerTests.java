package com.example.IT21_FinalProject;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, properties = "server.port=18080")
class HomeControllerTests {

	@Test
	void homeEndpointRendersTemplate() {
		try {
			HttpClient httpClient = HttpClient.newHttpClient();
			HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:18080/"))
					.GET()
					.build();
			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

			assertThat(response.statusCode()).isEqualTo(200);
			assertThat(response.body()).contains("Sign in to SignaSure");
		} catch (IOException | InterruptedException exception) {
			throw new RuntimeException(exception);
		}
	}

	@Test
	void adminDashboardAddsLiveStatsToModel() {
		JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
		HomeController controller = new HomeController(jdbcTemplate);
		MockHttpSession session = new MockHttpSession();
		session.setAttribute("userName", "Admin User");
		session.setAttribute("userEmail", "admin@example.com");

		when(jdbcTemplate.queryForObject(eq("SELECT role_id FROM \"user\" WHERE email = ?"), eq(String.class), eq("admin@example.com")))
				.thenReturn("ROL001");
		when(jdbcTemplate.queryForObject(eq("SELECT COUNT(*) FROM \"user\""), eq(Integer.class))).thenReturn(12);
		when(jdbcTemplate.queryForObject(eq("SELECT COUNT(*) FROM document"), eq(Integer.class))).thenReturn(9);
		when(jdbcTemplate.queryForObject(eq("SELECT COUNT(*) FROM digital_signature"), eq(Integer.class))).thenReturn(5);
		when(jdbcTemplate.queryForObject(eq("SELECT COUNT(*) FROM document WHERE document_status <> 'Signed'"), eq(Integer.class))).thenReturn(2);
		when(jdbcTemplate.queryForList(any(String.class))).thenReturn(List.of(Map.of("created_at", "2026-01-01 10:00:00", "event_type", "SIGN", "description", "Signed")));

		Model model = new ExtendedModelMap();
		String viewName = controller.adminDashboard(session, model);

		assertThat(viewName).isEqualTo("admin/admin-dashboard");
		assertThat(model.getAttribute("stats")).isNotNull();
		assertThat(model.getAttribute("recentActivity")).isNotNull();
	}
}